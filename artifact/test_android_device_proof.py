#!/usr/bin/env python3

from __future__ import annotations

import argparse
import contextlib
import copy
import datetime as dt
import io
import hashlib
import json
import os
import pathlib
import py_compile
import re
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

import android_device_proof
import android_emulator_control
import proof_to_byte_inputs
from process_identity import ProcessExecutionSnapshot, ProcessIdentity

# Independent immutable r2 fixture contract.  These literals intentionally do
# not import or derive from current or historical production shape constants.
PUBLISHED_V1_ROOT = "qperiapt-android-runtime-evidence-v1"
PUBLISHED_V1_MANIFEST_PATH = "MANIFEST.json"
PUBLISHED_V1_KIND = "qperiapt.android_runtime_evidence_bundle"
PUBLISHED_V1_SCHEMA = 1
PUBLISHED_V1_PROOF_SCHEMA = 3
PUBLISHED_V1_RUN_ID = "ba666ecf3aa279cb83a4218f4951a3e6"
PUBLISHED_V1_SOURCE_DATE_EPOCH = 1_784_262_215
PUBLISHED_V1_TAG_COMMIT = "5d1598f0ebf9c61e150e55ff398e457ca11f4629"
PUBLISHED_V1_SOURCE_TREE_SHA256 = (
    "7d1224619ab9992e3e10a6be61351835146473bbbc03c661ce8b5b0825078416"
)
PUBLISHED_V1_FILE_PATHS = {
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
PUBLISHED_V1_ARCHIVE_ENTRIES = {
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
PUBLISHED_V1_MANIFEST_FIELDS = frozenset(
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
PUBLISHED_V1_FILE_RECORD_FIELDS = frozenset({"bytes", "path", "sha256"})
PUBLISHED_V1_PROOF_FIELDS = frozenset(
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
PUBLISHED_V1_RESULT_FIELDS = frozenset(
    {"marker_sha256", "json_sha256", "status", "test_count", "passed_tests"}
)
PUBLISHED_V1_ARTIFACT_FIELDS = frozenset(
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
PUBLISHED_V1_ARTIFACT_LINKS = (
    ("aar_sha256", "aar"),
    ("aar_manifest_sha256", "aar_manifest"),
    ("smoke_apk_sha256", "smoke_apk"),
    ("apksigner_verify_sha256", "apksigner_verify"),
    ("zipalign_verify_sha256", "zipalign_verify"),
    ("logcat_sha256", "logcat"),
)
PUBLISHED_V1_EXPECTED_TESTS = (
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
)
PUBLISHED_V1_NATIVE_ABIS = ("arm64-v8a", "x86_64", "armeabi-v7a", "x86")
PUBLISHED_V1_BUNDLE_DEVICE = {
    "kind": "emulator",
    "abi": "arm64-v8a",
    "page_size": 16_384,
    "sdk": 35,
}
PUBLISHED_V1_PROOF_DEVICE = {
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
PUBLISHED_V1_PROOF_PATHS = {
    "aar": "target/abi2-platform-release-29555221955/candidate/q-periapt-android-0.1.0-alpha.2.aar",
    "aar_manifest": "target/abi2-platform-release-29555221955/candidate/q-periapt-android-0.1.0-alpha.2-MANIFEST.json",
    "smoke_apk": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-smoke.apk",
    "apksigner_verify": "target/abi2-platform-release-29555221955/android-runtime/proof/apksigner-verify.txt",
    "zipalign_verify": "target/abi2-platform-release-29555221955/android-runtime/proof/zipalign-verify.txt",
    "result_txt": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-device-result.txt",
    "result_json": "target/abi2-platform-release-29555221955/android-runtime/proof/qperiapt-android-device-result.json",
    "logcat": "target/abi2-platform-release-29555221955/android-runtime/proof/logcat.txt",
}


def create_private_adb_test_directory() -> pathlib.Path:
    for _ in range(100):
        directory = pathlib.Path("/tmp") / f"qperiapt-adb.{secrets.token_hex(4)}"
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            continue
        directory.chmod(0o700)
        return directory
    raise RuntimeError("could not allocate a private adb test directory")


def complete_proof_shape() -> dict[str, object]:
    native = {
        abi: {
            "ffi_so_sha256": "1" * 64,
            "jni_so_sha256": "2" * 64,
        }
        for abi in android_device_proof.REQUIRED_NATIVE_ABIS
    }
    console_port = 5584
    adb_port = console_port + 1
    registration_response = android_device_proof.emulator_registration_response_bytes(
        "connected",
        console_port=console_port,
        adb_port=adb_port,
    )
    private_adb = {
        "adb_profile": "macos-account",
        "identity_sha256": "4" * 64,
        "listener_descriptor_sha256": hashlib.sha256(b"7").hexdigest(),
        "server_status_sha256": "5" * 64,
        "listener_snapshot_sha256": "6" * 64,
    }
    external_adb = {
        "snapshot_sha256": "7" * 64,
        "routing_environment_sha256": "8" * 64,
        "routing_receipt_sha256": "9" * 64,
    }
    external_adb["transport_binding_sha256"] = (
        android_device_proof.emulator_routing_transport_binding_sha256(
            external_adb["snapshot_sha256"],
            external_adb["routing_environment_sha256"],
            private_adb,
        )
    )

    return {
        "schema": android_device_proof.PROOF_SCHEMA_VERSION,
        "generated_at": "2026-07-15T00:00:00Z",
        "git_commit": "a" * 40,
        "source_tree_dirty": False,
        "proof_source_tree_sha256": "b" * 64,
        "device_runtime_proof": True,
        "package_only": False,
        "release_candidate_mode": False,
        "run_id": "c" * 32,
        "package": "dev.qperiapt.androidsmoke",
        "paths": {
            key: f"target/android/{key}" for key in android_device_proof.PROOF_PATH_KEYS
        },
        "device": {
            "kind": "emulator",
            "serial_sha256_prefix": "3" * 12,
            "raw_serial_recorded": False,
            "manufacturer": "Google",
            "model": "Android SDK built for arm64",
            "abi": "arm64-v8a",
            "page_size": 16384,
            "sdk": 35,
            "release": "15",
            "fingerprint_sha256_prefix": "4" * 12,
        },
        "emulator_control": {
            "backend": {
                "identity": "qemu-system-aarch64-headless",
                "sha256": "1" * 64,
            },
            "ports": {"console": console_port, "adb": adb_port},
            "process_identity_sha256": "2" * 64,
            "listener_process_identity_sha256": "2" * 64,
            "listener_endpoints": [
                f"127.0.0.1:{console_port}",
                f"127.0.0.1:{adb_port}",
            ],
            "listener_snapshot_sha256": "3" * 64,
            "registration": {
                "accepted_response": "connected",
                "response_sha256": android_device_proof.sha256_bytes(
                    registration_response
                ),
            },
            "private_adb": private_adb,
            "external_adb": external_adb,
            "native_notifier": {
                "mode": android_device_proof.NATIVE_NOTIFIER_MODE,
                "port": android_device_proof.NATIVE_ADB_NOTIFIER_PORT,
                "admission_checkpoints": [
                    {"name": checkpoint.value, "receipt_sha256": "b" * 64}
                    for checkpoint in android_device_proof.ADB_ISOLATION_CHECKPOINTS
                ],
                "continuous_absence_claimed": False,
            },
        },
        "android": {
            "platform": "android-35",
            "build_tools": "36.0.0",
            "ndk": "29.0.14206865",
            "native_page_alignment": 16384,
            "min_sdk": 23,
            "target_sdk": 35,
            "adb_version": "Android Debug Bridge version 1.0.41",
            "apksigner_sha256": "5" * 64,
            "zipalign_sha256": "6" * 64,
        },
        "abi": {
            "major": 2,
            "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            "contract_sha256": "7" * 64,
            "runtime_library": "libq_periapt_ffi_abi2.so",
            "jni_library": "libqperiapt_jni_abi2.so",
            "legacy_library_names_present": False,
        },
        "result": {
            "marker_sha256": "8" * 64,
            "json_sha256": "9" * 64,
            "status": "pass",
            "test_count": len(android_device_proof.EXPECTED_TESTS),
            "passed_tests": list(android_device_proof.EXPECTED_TESTS),
        },
        "artifacts": {
            "aar_sha256": "a" * 64,
            "aar_manifest_sha256": "b" * 64,
            "smoke_apk_sha256": "c" * 64,
            "apksigner_verify_sha256": "d" * 64,
            "zipalign_verify_sha256": "e" * 64,
            "logcat_sha256": "f" * 64,
            "native": native,
        },
        "source_hashes": {
            name + "_sha256": "0" * 64 for name in android_device_proof.SOURCE_INPUTS
        },
    }


def current_results_for_proof(
    proof: dict[str, object],
    *,
    results_binding: str = "android_runtime",
) -> dict[str, object]:
    """Build the exact current-results projection for one schema-v6 proof."""

    if results_binding == "android_runtime":
        runtime_section = "android_device_runtime"
        runtime_status = "current_clean_tree_emulator_pass"
        proof["release_candidate_mode"] = True
    elif results_binding == "android_physical_runtime":
        runtime_section = "android_physical_runtime"
        runtime_status = "current_clean_tree_physical_pass"
    else:
        raise ValueError(f"unsupported fixture results binding: {results_binding}")
    proof["paths"]["aar"] = proof_manifest_aar_path = (
        "target/qperiapt-android-aar/q-periapt-android-0.1.3/"
        "q-periapt-android-0.1.3.aar"
    )
    proof["paths"]["aar_manifest"] = proof_manifest_path = (
        "target/qperiapt-android-aar/q-periapt-android-0.1.3/MANIFEST.json"
    )
    run_id = proof["run_id"]
    source_digest = proof["proof_source_tree_sha256"]
    source_commit = proof["git_commit"]
    device = proof["device"]
    android = proof["android"]
    result = proof["result"]
    artifacts = proof["artifacts"]
    return {
        "android_aar": {
            "aar_path": proof_manifest_aar_path,
            "aar_sha256": artifacts["aar_sha256"],
            "current_source_status": "current_clean_tree_package_pass",
            "manifest_generated_at": proof["generated_at"],
            "manifest_path": proof_manifest_path,
            "manifest_schema": 4,
            "manifest_sha256": artifacts["aar_manifest_sha256"],
            "proof_source_tree_sha256": source_digest,
            "source_commit": source_commit,
            "source_tree_dirty": False,
            "status": "pass",
            "targets": list(android_device_proof.REQUIRED_NATIVE_ABIS),
        },
        runtime_section: {
            "android_sdk": device["sdk"],
            "build_tools": android["build_tools"],
            "covered_tests": result["passed_tests"],
            "current_source_status": runtime_status,
            "device_abi": device["abi"],
            "device_kind": device["kind"],
            "page_size": device["page_size"],
            "proof_generated_at": proof["generated_at"],
            "proof_path": (
                f"target/qperiapt-android-device-smoke-runs/{run_id}/proof/"
                "qperiapt-android-device-proof.json"
            ),
            "proof_schema": proof["schema"],
            "proof_sha256": "f" * 64,
            "proof_source_tree_sha256": source_digest,
            "release_candidate_mode": proof["release_candidate_mode"],
            "run_id": run_id,
            "source_commit": source_commit,
            "source_tree_dirty": proof["source_tree_dirty"],
            "status": result["status"],
        },
        "proof_source_tree_sha256": source_digest,
        "provenance": {"snapshot_commit": source_commit},
    }


def write_emulator_isolation_receipts(
    directory: pathlib.Path,
    *,
    run_id: str,
    private_adb: dict[str, str],
) -> tuple[
    pathlib.Path,
    dict[android_device_proof.AdbIsolationCheckpoint, pathlib.Path],
]:
    """Write canonical private fixtures matching the schema-v6 projection."""

    directory.mkdir(parents=True, exist_ok=True)
    checkpoint_paths = {}
    for checkpoint in android_device_proof.ADB_ISOLATION_CHECKPOINTS:
        path = directory / android_device_proof.ADB_ISOLATION_CHECKPOINT_LEAVES[
            checkpoint
        ]
        path.write_bytes(
            android_device_proof.canonical_json(
                {
                    "schema": android_device_proof.ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
                    "kind": android_device_proof.ADB_ISOLATION_RECEIPT_KIND,
                    "run_id": run_id,
                    "checkpoint": checkpoint.value,
                    "ports": {
                        str(android_device_proof.DEFAULT_ADB_SERVER_PORT): {
                            "ipv4": "connection_refused",
                            "ipv6": "connection_refused",
                        },
                        str(android_device_proof.NATIVE_ADB_NOTIFIER_PORT): {
                            "ipv4": "connection_refused",
                            "ipv6": "connection_refused",
                        },
                    },
                }
            )
        )
        path.chmod(0o600)
        checkpoint_paths[checkpoint] = path

    adb_snapshot_sha256 = "7" * 64
    routing_environment_sha256 = "8" * 64
    routing_path = directory / android_device_proof.EMULATOR_ROUTING_RECEIPT_LEAF
    routing_path.write_bytes(
        android_device_proof.canonical_json(
            {
                "schema": android_emulator_control.EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
                "kind": android_emulator_control.EMULATOR_ROUTING_RECEIPT_KIND,
                "run_id": run_id,
                "mode": android_emulator_control.EMULATOR_ROUTING_MODE,
                "adb_snapshot_sha256": adb_snapshot_sha256,
                "routing_environment_sha256": routing_environment_sha256,
                "transport_binding_sha256": (
                    android_device_proof.emulator_routing_transport_binding_sha256(
                        adb_snapshot_sha256,
                        routing_environment_sha256,
                        private_adb,
                    )
                ),
                "private_adb": private_adb,
                "native_notifier_port": android_device_proof.NATIVE_ADB_NOTIFIER_PORT,
                "private_socket_kind": "localfilesystem",
                "raw_paths_recorded": False,
            }
        )
    )
    routing_path.chmod(0o600)
    return routing_path, checkpoint_paths


def build_published_runtime_bundle_v1_fixture(
    root: pathlib.Path,
    *,
    bundle_schema: int = PUBLISHED_V1_SCHEMA,
    proof_schema: int = PUBLISHED_V1_PROOF_SCHEMA,
    root_name: str | None = None,
) -> tuple[pathlib.Path, str, str, str]:
    """Build real deterministic v1 archive bytes without mocking the verifier."""

    root = root.resolve(strict=True)
    stage = root / "published-v1-stage"
    stage.mkdir()
    file_paths = PUBLISHED_V1_FILE_PATHS
    records: dict[str, dict[str, object]] = {}
    for key, relative in file_paths.items():
        if key == "proof":
            continue
        path = stage / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"published-v1-fixture-{key}\n".encode("ascii"))
        records[key] = android_device_proof.bundle_file_record(path, relative)

    native = {
        abi: {"ffi_so_sha256": "1" * 64, "jni_so_sha256": "2" * 64}
        for abi in PUBLISHED_V1_NATIVE_ABIS
    }
    proof = {
        "schema": proof_schema,
        "generated_at": "2026-07-17T04:45:32.426321Z",
        "git_commit": PUBLISHED_V1_TAG_COMMIT,
        "source_tree_dirty": False,
        "proof_source_tree_sha256": PUBLISHED_V1_SOURCE_TREE_SHA256,
        "device_runtime_proof": True,
        "package_only": False,
        "release_candidate_mode": True,
        "run_id": PUBLISHED_V1_RUN_ID,
        "package": "dev.qperiapt.androidsmoke",
        "paths": dict(PUBLISHED_V1_PROOF_PATHS),
        "device": dict(PUBLISHED_V1_PROOF_DEVICE),
        "android": {
            "ndk": "29.0.14206865",
            "platform": "android-35",
            "build_tools": "36.0.0",
            "adb_version": "Android Debug Bridge version 1.0.41",
            "apksigner_sha256": "3" * 64,
            "zipalign_sha256": "4" * 64,
            "min_sdk": 23,
            "target_sdk": 35,
            "native_page_alignment": 16_384,
        },
        "abi": {
            "major": 2,
            "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            "contract_sha256": "5" * 64,
            "runtime_library": "libq_periapt_ffi_abi2.so",
            "jni_library": "libqperiapt_jni_abi2.so",
            "legacy_library_names_present": False,
        },
        "result": {
            "marker_sha256": records["result_txt"]["sha256"],
            "json_sha256": records["result_json"]["sha256"],
            "status": "pass",
            "test_count": len(PUBLISHED_V1_EXPECTED_TESTS),
            "passed_tests": list(PUBLISHED_V1_EXPECTED_TESTS),
        },
        "artifacts": {
            "aar_sha256": records["aar"]["sha256"],
            "aar_manifest_sha256": records["aar_manifest"]["sha256"],
            "smoke_apk_sha256": records["smoke_apk"]["sha256"],
            "apksigner_verify_sha256": records["apksigner_verify"]["sha256"],
            "zipalign_verify_sha256": records["zipalign_verify"]["sha256"],
            "logcat_sha256": records["logcat"]["sha256"],
            "native": native,
        },
        "source_hashes": {"published_fixture_sha256": "6" * 64},
    }
    proof_path = stage / file_paths["proof"]
    proof_path.write_bytes(android_device_proof.canonical_json(proof))
    records["proof"] = android_device_proof.bundle_file_record(
        proof_path, file_paths["proof"]
    )
    manifest = {
        "schema_version": bundle_schema,
        "kind": PUBLISHED_V1_KIND,
        "source_date_epoch": PUBLISHED_V1_SOURCE_DATE_EPOCH,
        "git_commit": PUBLISHED_V1_TAG_COMMIT,
        "run_id": PUBLISHED_V1_RUN_ID,
        "release_candidate_mode": True,
        "device": dict(PUBLISHED_V1_BUNDLE_DEVICE),
        "raw_serial_recorded": False,
        "files": records,
    }
    manifest_path = stage / PUBLISHED_V1_MANIFEST_PATH
    manifest_path.write_bytes(android_device_proof.canonical_json(manifest))
    bundle = root / "published-v1-fixture.zip"
    android_device_proof.create_zip(
        stage,
        bundle,
        root_name=root_name or PUBLISHED_V1_ROOT,
        mtime=PUBLISHED_V1_SOURCE_DATE_EPOCH,
    )
    return (
        bundle,
        android_device_proof.sha256_file(bundle),
        android_device_proof.sha256_file(manifest_path),
        android_device_proof.sha256_file(proof_path),
    )


class AndroidAdbIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.account_home = pathlib.Path(self.temp_dir.name) / "account-home"
        self.account_home.mkdir(mode=0o700)
        self.account_home.chmod(0o700)
        self.android_dir = self.account_home / ".android"
        self.android_dir.mkdir(mode=0o700)
        self.android_dir.chmod(0o700)
        self.private_key = self.android_dir / "adbkey"
        self.public_key = self.android_dir / "adbkey.pub"
        self.private_key.write_text("private fixture\n", encoding="utf-8")
        self.public_key.write_text("public fixture\n", encoding="utf-8")
        self.private_key.chmod(0o600)
        self.public_key.chmod(0o644)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_registered_linux_adb_evidence_binds_listen_state_profile_and_fd(
        self,
    ) -> None:
        run_id = "d" * 32
        run_root = (
            self.account_home
            / "target"
            / android_device_proof.ANDROID_RUNS_ROOT_LEAF
            / run_id
        )
        proof_root = run_root / "proof"
        work_root = run_root / "work"
        proof_root.mkdir(parents=True)
        work_root.mkdir()
        status_path = proof_root / android_device_proof.PRIVATE_ADB_STATUS_REGISTERED_LEAF
        listener_path = (
            proof_root / android_device_proof.PRIVATE_ADB_LISTENER_REGISTERED_LEAF
        )
        socket_path = "/tmp/qperiapt-adb.A1b2C3d4/adb.sock"
        status_path.write_text(
            f'executable_absolute_path: "{work_root / f"adb-{run_id}"}"\n'
            f'keystore_path: "{self.account_home / ".android/adbkey"}"\n'
            "mdns_enabled: false\n",
            encoding="utf-8",
        )
        listener_bytes = (
            f"p321\nu{os.geteuid()}\n"
            f"f7\nn{socket_path} type=STREAM\nTST=LISTEN\n"
            f"f8\nn{socket_path} type=STREAM\nTST=CONNECTED\n"
        ).encode("ascii")
        listener_path.write_bytes(listener_bytes)
        status_path.chmod(0o600)
        listener_path.chmod(0o600)
        private_identity = f"321:{os.geteuid()}:456:789"
        private_adb = {
            "adb_profile": "linux-system",
            "identity_sha256": android_device_proof.process_identity_sha256(
                private_identity,
                "private adb process identity",
            ),
            "listener_descriptor_sha256": hashlib.sha256(b"7").hexdigest(),
            "listener_snapshot_sha256": hashlib.sha256(listener_bytes).hexdigest(),
            "server_status_sha256": android_device_proof.sha256_file(status_path),
        }
        routing_path = proof_root / android_device_proof.EMULATOR_ROUTING_RECEIPT_LEAF

        def write_routing() -> None:
            snapshot = "2" * 64
            environment = "3" * 64
            routing_path.write_bytes(
                android_device_proof.canonical_json(
                    {
                        "schema": android_emulator_control.EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
                        "kind": android_emulator_control.EMULATOR_ROUTING_RECEIPT_KIND,
                        "run_id": run_id,
                        "mode": android_emulator_control.EMULATOR_ROUTING_MODE,
                        "adb_snapshot_sha256": snapshot,
                        "routing_environment_sha256": environment,
                        "transport_binding_sha256": android_device_proof.emulator_routing_transport_binding_sha256(
                            snapshot,
                            environment,
                            private_adb,
                        ),
                        "private_adb": private_adb,
                        "native_notifier_port": android_device_proof.NATIVE_ADB_NOTIFIER_PORT,
                        "private_socket_kind": "localfilesystem",
                        "raw_paths_recorded": False,
                    }
                )
            )
            routing_path.chmod(0o600)

        write_routing()
        with mock.patch.object(
            android_device_proof,
            "current_account_home",
            return_value=self.account_home,
        ):
            observed = android_device_proof._read_registered_private_adb_evidence(
                routing_receipt_path=routing_path,
                run_id=run_id,
                private_adb_identity=private_identity,
            )
            self.assertEqual(observed, private_adb)

            listener_path.write_bytes(
                listener_bytes.replace(b"TST=LISTEN", b"TST=CONNECTED")
            )
            with self.assertRaisesRegex(SystemExit, "bound listening descriptor"):
                android_device_proof._read_registered_private_adb_evidence(
                    routing_receipt_path=routing_path,
                    run_id=run_id,
                    private_adb_identity=private_identity,
                )
            listener_path.write_bytes(listener_bytes)
            listener_path.chmod(0o600)

            private_adb["adb_profile"] = "macos-account"
            write_routing()
            with self.assertRaisesRegex(SystemExit, "endpoint encoding|socket state"):
                android_device_proof._read_registered_private_adb_evidence(
                    routing_receipt_path=routing_path,
                    run_id=run_id,
                    private_adb_identity=private_identity,
                )

    def test_owner_controlled_identity_passes(self) -> None:
        android_device_proof.validate_adb_identity_directory(self.android_dir)
        android_device_proof.validate_account_adb_identity(
            self.account_home, account_home=self.account_home
        )

    def test_avd_home_verifier_accepts_only_the_fixed_runtime_selection(self) -> None:
        fixed_home = self.account_home / "private-state" / "avd-home"
        arguments = argparse.Namespace(
            run_id="a" * 32,
            avd_home=fixed_home,
            adb_profile="macos-account",
            device_abi="arm64-v8a",
        )
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "avd_home_directory",
                return_value=fixed_home,
            ),
            mock.patch.object(
                android_device_proof.runtime_state,
                "validate_runtime_avd_selection",
            ) as validate,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            android_device_proof.verify_avd_home(arguments)
        validate.assert_called_once_with("macos-account", "arm64-v8a")
        self.assertEqual(output.getvalue(), "ANDROID_AVD_HOME_VERIFY_PASS\n")

        wrong = copy.copy(arguments)
        wrong.avd_home = self.android_dir / "avd"
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "avd_home_directory",
                return_value=fixed_home,
            ),
            mock.patch.object(
                android_device_proof.runtime_state,
                "validate_runtime_avd_selection",
            ) as rejected_validate,
            self.assertRaisesRegex(SystemExit, "fixed private runtime AVD"),
        ):
            android_device_proof.verify_avd_home(wrong)
        rejected_validate.assert_not_called()

        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "avd_home_directory",
                return_value=fixed_home,
            ),
            mock.patch.object(
                android_device_proof.runtime_state,
                "validate_runtime_avd_selection",
                side_effect=android_device_proof.runtime_state.AndroidRuntimeStateError(
                    "selected AVD ini is inconsistent"
                ),
            ),
            self.assertRaisesRegex(SystemExit, "selected AVD ini is inconsistent"),
        ):
            android_device_proof.verify_avd_home(arguments)

    def test_different_or_group_writable_account_home_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "must match the current account home"):
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home.parent
            )
        self.account_home.chmod(0o770)
        with self.assertRaisesRegex(SystemExit, "home must not be writable by group"):
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home
            )

    def test_group_writable_identity_directory_is_rejected(self) -> None:
        self.android_dir.chmod(0o770)
        with self.assertRaisesRegex(SystemExit, "must not be writable by group"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_symlink_identity_directory_is_rejected(self) -> None:
        link = pathlib.Path(self.temp_dir.name) / "android-link"
        link.symlink_to(self.android_dir, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "non-symlink directory"):
            android_device_proof.validate_adb_identity_directory(link)

    def test_insecure_or_empty_key_is_rejected(self) -> None:
        self.private_key.chmod(0o640)
        with self.assertRaisesRegex(SystemExit, "must not be accessible"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)
        self.private_key.chmod(0o600)
        self.public_key.write_bytes(b"")
        with self.assertRaisesRegex(SystemExit, "must not be empty"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_non_key_leaf_cannot_substitute_for_regular_key(self) -> None:
        self.private_key.unlink()
        self.private_key.mkdir(mode=0o700)
        with self.assertRaisesRegex(SystemExit, "regular non-symlink file"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_fifo_key_is_rejected_without_blocking(self) -> None:
        self.private_key.unlink()
        os.mkfifo(self.private_key, mode=0o600)
        artifact_directory = pathlib.Path(__file__).resolve().parent
        script = (
            "import pathlib, sys; "
            f"sys.path.insert(0, {str(artifact_directory)!r}); "
            "import android_device_proof; "
            "android_device_proof.validate_adb_identity_directory("
            f"pathlib.Path({str(self.android_dir)!r}))"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("regular non-symlink file", completed.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_allow_acl_on_every_identity_node_is_rejected(self) -> None:
        for path in (
            self.account_home,
            self.android_dir,
            self.private_key,
            self.public_key,
        ):
            with self.subTest(path=path):
                subprocess.run(
                    ["/bin/chmod", "+a", "everyone allow readattr", str(path)],
                    check=True,
                )
                try:
                    with self.assertRaisesRegex(SystemExit, "allow ACL is forbidden"):
                        android_device_proof.validate_account_adb_identity(
                            self.account_home, account_home=self.account_home
                        )
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(path)], check=True)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_deny_only_home_acl_is_accepted(self) -> None:
        subprocess.run(
            ["/bin/chmod", "+a", "everyone deny delete", str(self.account_home)],
            check=True,
        )
        try:
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home
            )
        finally:
            subprocess.run(["/bin/chmod", "-N", str(self.account_home)], check=True)

    def test_adb_server_status_requires_exact_executable_and_keystore(self) -> None:
        executable = pathlib.Path(sys.executable).resolve()
        expected_keystore = self.android_dir / "adbkey"
        fields = android_device_proof.parse_adb_server_status(
            f'executable_absolute_path: "{executable}"\n'
            f'keystore_path: "{expected_keystore}"\n'
            "mdns_enabled: false\n"
        )
        android_device_proof.validate_adb_server_status_fields(
            fields,
            selected_adb=executable,
            home_directory=self.account_home,
            account_home=self.account_home,
        )
        fields["keystore_path"] = str(self.android_dir / "different-key")
        with self.assertRaisesRegex(SystemExit, "keystore differs"):
            android_device_proof.validate_adb_server_status_fields(
                fields,
                selected_adb=executable,
                home_directory=self.account_home,
                account_home=self.account_home,
            )
        fields["keystore_path"] = str(expected_keystore)
        fields["mdns_enabled"] = True
        with self.assertRaisesRegex(SystemExit, "disable mDNS"):
            android_device_proof.validate_adb_server_status_fields(
                fields,
                selected_adb=executable,
                home_directory=self.account_home,
                account_home=self.account_home,
            )

    def test_adb_server_status_rejects_missing_duplicate_or_malformed_fields(
        self,
    ) -> None:
        invalid_statuses = (
            'executable_absolute_path: "/bin/false"\n',
            'keystore_path: "/tmp/key"\nkeystore_path: "/tmp/key"\n',
            "keystore_path: not-json\n",
            'keystore_path: {"path":"a","path":"b"}\n',
            'keystore_path: {"outer":{"path":"a","path":"b"}}\n',
            "mdns_enabled: NaN\n",
            "mdns_enabled: Infinity\n",
            "mdns_enabled: -Infinity\n",
            "mdns_enabled: 1e999\n",
            "mdns_enabled: " + ("9" * 5000) + "\n",
        )
        for status in invalid_statuses:
            with self.subTest(status=status):
                with self.assertRaises(SystemExit):
                    android_device_proof.parse_adb_server_status(status)

    def test_lsof_listener_requires_one_canonical_pid_and_uid(self) -> None:
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p123\nu501\nf18\nn127.0.0.1:5037\n",
                expected_endpoint="127.0.0.1:5037",
                dialect=android_device_proof.OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=None,
            ),
            (123, 501),
        )
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p124\nu501\nf19\nn/tmp/qperiapt-adb.12345678/adb.sock\n",
                expected_endpoint="/tmp/qperiapt-adb.12345678/adb.sock",
                dialect=android_device_proof.OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=None,
            ),
            (124, 501),
        )
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p125\nu501\nf20\n"
                "n/tmp/qperiapt-adb.12345678/adb.sock type=STREAM\nTST=LISTEN\n",
                expected_endpoint="/tmp/qperiapt-adb.12345678/adb.sock",
                dialect=android_device_proof.OwnedUnixListenerDialect.LINUX,
                expected_listener_descriptor=None,
            ),
            (125, 501),
        )
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p126\nu501\n"
                "f20\nn/tmp/qperiapt-adb.12345678/adb.sock type=STREAM\nTST=LISTEN\n"
                "f21\nn/tmp/qperiapt-adb.12345678/adb.sock type=STREAM\nTST=CONNECTED\n",
                expected_endpoint="/tmp/qperiapt-adb.12345678/adb.sock",
                dialect=android_device_proof.OwnedUnixListenerDialect.LINUX,
                expected_listener_descriptor=20,
            ),
            (126, 501),
        )
        invalid_outputs = (
            "",
            "p0123\nu501\nf18\n",
            "p123\nf18\n",
            "p123\nu501\np124\nu501\n",
            "p123\nu501\nu501\n",
            "p123\nu501\ncunknown\n",
            "p123\nu501\nf18\nn*:5037\n",
            "p123\nu501\nf18\nn127.0.0.1:5037 type=STREAM\n",
        )
        for output in invalid_outputs:
            with self.subTest(output=output):
                with self.assertRaises(SystemExit):
                    android_device_proof.parse_lsof_adb_listener(
                        output,
                        expected_endpoint="127.0.0.1:5037",
                        dialect=android_device_proof.OwnedUnixListenerDialect.DARWIN,
                        expected_listener_descriptor=None,
                    )

    def test_owned_emulator_listeners_bind_exact_child_and_port_pair(self) -> None:
        uid = os.geteuid()
        output = f"p123\nu{uid}\nf18\nn127.0.0.1:5584\nf19\nn127.0.0.1:5585\n"
        self.assertEqual(
            android_device_proof.parse_lsof_owned_emulator_listeners(
                output,
                expected_pid=123,
                console_port=5584,
                adb_port=5585,
            ),
            uid,
        )
        dual_stack = output + "f20\nn[::1]:5584\nf21\nn[::1]:5585\n"
        self.assertEqual(
            android_device_proof.parse_lsof_owned_emulator_listeners(
                dual_stack,
                expected_pid=123,
                console_port=5584,
                adb_port=5585,
            ),
            uid,
        )
        invalid = (
            output.replace("p123", "p124"),
            output.replace(f"u{uid}", f"u{uid + 1}"),
            output.replace(f"u{uid}", f"u0{uid}"),
            output.replace("127.0.0.1:5585", "*:5585"),
            output + "f20\nn127.0.0.1:8554\n",
            dual_stack.replace("[::1]:5584", "[::]:5584"),
            dual_stack.replace("[::1]:5585", "[2001:db8::1]:5585"),
            output.replace("f19\nn127.0.0.1:5585\n", ""),
            output.replace("p123", "p0123"),
            output.replace("f19", "f18"),
            output.replace("f18\nn127.0.0.1:5584\n", "n127.0.0.1:5584\n"),
            output.replace("f19\nn127.0.0.1:5585\n", "f19\n"),
            output.replace(f"u{uid}\n", "").replace("f18\n", f"f18\nu{uid}\n"),
            output + "p125\n",
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate), self.assertRaises(SystemExit):
                android_device_proof.parse_lsof_owned_emulator_listeners(
                    candidate,
                    expected_pid=123,
                    console_port=5584,
                    adb_port=5585,
                )
        for ports in ((5583, 5584), (5584, 5586), (5586, 5587)):
            with self.subTest(ports=ports), self.assertRaises(SystemExit):
                android_device_proof.parse_lsof_owned_emulator_listeners(
                    output,
                    expected_pid=123,
                    console_port=ports[0],
                    adb_port=ports[1],
                )

    def test_direct_owned_process_pid_commands_are_not_public(self) -> None:
        self.assertFalse(hasattr(android_device_proof, "verify_owned_process"))
        self.assertFalse(hasattr(android_device_proof, "wait_owned_process_exec"))
        parser = android_device_proof.build_parser()
        for arguments in (
            ["verify-owned-process", "--expected-pid", "123"],
            ["wait-owned-process-exec", "--expected-pid", "123"],
        ):
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                parser.parse_args(arguments)
            self.assertEqual(raised.exception.code, 2)

    def test_emulator_backend_path_is_fixed_by_host_and_device_abi(self) -> None:
        emulator_directory = self.account_home / "sdk" / "emulator"
        emulator_directory.mkdir(parents=True)
        launcher = emulator_directory / "emulator"
        launcher.write_bytes(b"launcher")
        launcher.chmod(0o700)
        cases = (
            ("darwin", "arm64", "arm64-v8a", "darwin-aarch64", "aarch64"),
            ("darwin", "x86_64", "x86_64", "darwin-x86_64", "x86_64"),
            ("linux", "aarch64", "arm64-v8a", "linux-aarch64", "aarch64"),
            ("linux", "x86_64", "x86_64", "linux-x86_64", "x86_64"),
        )
        for system, machine, abi, host_directory, qemu_architecture in cases:
            backend = (
                emulator_directory
                / "qemu"
                / host_directory
                / f"qemu-system-{qemu_architecture}-headless"
            )
            backend.parent.mkdir(parents=True, exist_ok=True)
            backend.write_bytes(b"backend")
            backend.chmod(0o700)
            with (
                self.subTest(system=system, machine=machine, abi=abi),
                mock.patch.object(android_device_proof.sys, "platform", system),
                mock.patch.object(
                    android_device_proof.platform, "machine", return_value=machine
                ),
            ):
                self.assertEqual(
                    android_device_proof.emulator_backend_path(launcher, abi),
                    backend.resolve(),
                )

        for system, machine, abi in (
            ("darwin", "arm64", "x86_64"),
            ("linux", "x86_64", "arm64-v8a"),
            ("win32", "amd64", "x86_64"),
        ):
            with (
                self.subTest(system=system, machine=machine, abi=abi),
                mock.patch.object(android_device_proof.sys, "platform", system),
                mock.patch.object(
                    android_device_proof.platform, "machine", return_value=machine
                ),
                self.assertRaises(SystemExit),
            ):
                android_device_proof.emulator_backend_path(launcher, abi)

        symlink = emulator_directory / "emulator-link"
        symlink.symlink_to(launcher)
        with self.assertRaisesRegex(SystemExit, "must not be a symlink"):
            android_device_proof.emulator_backend_path(symlink, "arm64-v8a")

        backend = (
            emulator_directory
            / "qemu"
            / "darwin-aarch64"
            / "qemu-system-aarch64-headless"
        )
        backend.unlink()
        backend.symlink_to(launcher)
        with (
            mock.patch.object(android_device_proof.sys, "platform", "darwin"),
            mock.patch.object(
                android_device_proof.platform, "machine", return_value="arm64"
            ),
            self.assertRaisesRegex(SystemExit, "must not be a symlink"),
        ):
            android_device_proof.emulator_backend_path(launcher, "arm64-v8a")

    def test_default_adb_endpoint_probe_fails_closed(self) -> None:
        with mock.patch.object(
            android_device_proof, "probe_adb_loopback_absence"
        ) as probe:
            android_device_proof.assert_default_adb_server_absent(argparse.Namespace())
        probe.assert_called_once_with()

        with (
            mock.patch.object(
                android_device_proof,
                "probe_adb_loopback_absence",
                side_effect=android_device_proof.AndroidEmulatorControlError(
                    "native notifier endpoint did not refuse"
                ),
            ),
            self.assertRaisesRegex(SystemExit, "native notifier endpoint"),
        ):
            android_device_proof.assert_default_adb_server_absent(argparse.Namespace())

    def test_adb_listener_identity_rejects_wrong_process_or_environment(self) -> None:
        executable = pathlib.Path(sys.executable).resolve()
        uid = os.geteuid()

        def validate(**overrides: object) -> str:
            arguments: dict[str, object] = {
                "pid": 123,
                "reported_uid": uid,
                "process_uid": uid,
                "started_at": 456,
                "started_subsecond": 789,
                "executable": executable,
                "environment": {"HOME": str(self.account_home)},
                "selected_adb": executable,
                "account_home": self.account_home,
                "expected_identity": None,
            }
            arguments.update(overrides)
            return android_device_proof.validate_adb_listener_identity(**arguments)

        self.assertEqual(validate(), f"123:{uid}:456:789")
        private_environment = {
            "HOME": str(self.account_home),
            "ADB_SERVER_SOCKET": "localfilesystem:/tmp/qperiapt-adb.12345678/adb.sock",
            "ADB_VENDOR_KEYS": str(self.private_key),
            "ADB_MDNS": "0",
            "ADB_MDNS_AUTO_CONNECT": "0",
            "ADB_USB": "1",
            "ADB_EMU": "0",
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        }
        private_forbidden_environment = (
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
        )
        self.assertEqual(
            validate(
                environment=private_environment,
                expected_environment={
                    "ADB_SERVER_SOCKET": private_environment["ADB_SERVER_SOCKET"],
                    "ADB_VENDOR_KEYS": private_environment["ADB_VENDOR_KEYS"],
                    "ADB_MDNS": "0",
                    "ADB_MDNS_AUTO_CONNECT": "0",
                    "ADB_USB": "1",
                    "ADB_EMU": "0",
                    "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
                },
                forbidden_environment=private_forbidden_environment,
            ),
            f"123:{uid}:456:789",
        )
        invalid_overrides = (
            {"reported_uid": uid + 1},
            {"executable": pathlib.Path("/bin/false")},
            {"environment": {"HOME": str(self.account_home), "ADB_VENDOR_KEYS": ""}},
            {"environment": {"HOME": "/different"}},
            {"expected_identity": "123:0:456:789"},
            {
                "environment": private_environment,
                "expected_environment": {
                    "ADB_SERVER_SOCKET": "localfilesystem:/tmp/wrong/adb.sock",
                    "ADB_VENDOR_KEYS": str(self.private_key),
                    "ADB_MDNS": "0",
                    "ADB_MDNS_AUTO_CONNECT": "0",
                    "ADB_USB": "1",
                    "ADB_EMU": "0",
                    "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
                },
                "forbidden_environment": private_forbidden_environment,
            },
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises(SystemExit):
                    validate(**overrides)

    def test_private_adb_socket_requires_owned_directory_and_exact_socket_leaf(
        self,
    ) -> None:
        directory = create_private_adb_test_directory()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            arguments = argparse.Namespace(directory=directory, state="absent")
            android_device_proof.verify_private_adb_socket(arguments)

            socket_path = directory / "adb.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(socket_path))
            android_device_proof.verify_private_adb_socket(
                argparse.Namespace(directory=directory, state="present")
            )
            with self.assertRaisesRegex(SystemExit, "already exists"):
                android_device_proof.verify_private_adb_socket(arguments)
            listener.close()
            socket_path.unlink()

            os.mkfifo(socket_path, mode=0o600)
            with self.assertRaisesRegex(SystemExit, "not a socket"):
                android_device_proof.verify_private_adb_socket(
                    argparse.Namespace(directory=directory, state="present")
                )
            socket_path.unlink()

            directory.chmod(0o770)
            with self.assertRaisesRegex(SystemExit, "writable by group"):
                android_device_proof.verify_private_adb_socket(arguments)
            directory.chmod(0o750)
            with self.assertRaisesRegex(SystemExit, "mode 0700"):
                android_device_proof.verify_private_adb_socket(arguments)
        finally:
            directory.chmod(0o700)

    def test_private_listener_cli_binds_endpoint_pid_and_environment(self) -> None:
        endpoint = "/tmp/qperiapt-adb.12345678/adb.sock"
        lsof_output = self.account_home / "listener.txt"
        lsof_output.write_text(
            f"p123\nu{os.geteuid()}\nf18\nn{endpoint}\n", encoding="utf-8"
        )
        lsof_output = lsof_output.resolve()
        environment = {
            "HOME": str(self.account_home),
            "ADB_SERVER_SOCKET": f"localfilesystem:{endpoint}",
            "ADB_VENDOR_KEYS": str(self.private_key),
            "ADB_MDNS": "0",
            "ADB_MDNS_AUTO_CONNECT": "0",
            "ADB_USB": "1",
            "ADB_EMU": "0",
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        }
        arguments = argparse.Namespace(
            run_id="a" * 32,
            lsof_output=lsof_output,
            adb=pathlib.Path(sys.executable),
            expected_endpoint=endpoint,
            expected_pid=123,
            expected_identity=None,
            expected_server_socket=f"localfilesystem:{endpoint}",
            expected_vendor_keys=str(self.private_key),
            expected_mdns="0",
            expected_transport_kind="physical",
        )
        process_identity = ProcessIdentity(
            pid=123,
            uid=os.geteuid(),
            started_at=456,
            started_subsecond=789,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        execution = ProcessExecutionSnapshot(
            identity=process_identity,
            argv=(str(pathlib.Path(sys.executable).resolve()),),
            environment=environment,
        )
        receipt = types.SimpleNamespace(
            run_id=arguments.run_id,
            adb_server_started=True,
            adb_server_pid=123,
            adb_profile="macos-account",
            adb_listener_descriptor=None,
        )
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "load_owned_runtime_receipt",
                return_value=receipt,
            ),
            mock.patch.object(
                android_device_proof,
                "process_execution_snapshot",
                return_value=execution,
            ),
            mock.patch.object(
                android_device_proof,
                "current_account_home",
                return_value=self.account_home,
            ),
        ):
            android_device_proof.verify_adb_listener(arguments)
            receipt.adb_listener_descriptor = 18
            lsof_output.write_text(
                f"p123\nu{os.geteuid()}\nf19\nn{endpoint}\nf18\nn{endpoint}\n",
                encoding="utf-8",
            )
            android_device_proof.verify_adb_listener(arguments)
            wrong_socket = copy.copy(arguments)
            wrong_socket.expected_server_socket = (
                "localfilesystem:/tmp/qperiapt-adb.87654321/adb.sock"
            )
            with self.assertRaisesRegex(SystemExit, "does not name"):
                android_device_proof.verify_adb_listener(wrong_socket)
            missing_pid = copy.copy(arguments)
            missing_pid.expected_pid = None
            with self.assertRaisesRegex(SystemExit, "requires its owned pid"):
                android_device_proof.verify_adb_listener(missing_pid)

        wrong_pid = copy.copy(arguments)
        wrong_pid.expected_pid = 124
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "load_owned_runtime_receipt",
                return_value=receipt,
            ),
            mock.patch.object(
                android_device_proof, "process_execution_snapshot"
            ) as inspect,
            self.assertRaisesRegex(SystemExit, "pid differs"),
        ):
            android_device_proof.verify_adb_listener(wrong_pid)
        inspect.assert_not_called()

        wrong_run = copy.copy(arguments)
        wrong_run.run_id = "b" * 32
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "load_owned_runtime_receipt",
                return_value=receipt,
            ),
            mock.patch.object(
                android_device_proof, "process_execution_snapshot"
            ) as inspect,
            self.assertRaisesRegex(SystemExit, "owned server receipt"),
        ):
            android_device_proof.verify_adb_listener(wrong_run)
        inspect.assert_not_called()

        malformed_run = copy.copy(arguments)
        malformed_run.run_id = "not-a-run-id"
        with (
            mock.patch.object(
                android_device_proof.runtime_state,
                "load_owned_runtime_receipt",
                return_value=receipt,
            ),
            mock.patch.object(
                android_device_proof, "process_execution_snapshot"
            ) as inspect,
            self.assertRaisesRegex(SystemExit, "cannot load owned adb listener receipt"),
        ):
            android_device_proof.verify_adb_listener(malformed_run)
        inspect.assert_not_called()

    def test_private_adb_socket_rejects_wrong_shape_and_symlink_leaf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wrong-adb.", dir="/tmp") as raw:
            directory = pathlib.Path(raw)
            directory.chmod(0o700)
            with self.assertRaisesRegex(SystemExit, "fixed-shape child"):
                android_device_proof.verify_private_adb_socket(
                    argparse.Namespace(directory=directory, state="absent")
                )

        directory = create_private_adb_test_directory()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        target = directory / "target"
        target.write_bytes(b"not a socket")
        (directory / "adb.sock").symlink_to(target)
        with self.assertRaisesRegex(SystemExit, "not a socket"):
            android_device_proof.verify_private_adb_socket(
                argparse.Namespace(directory=directory, state="present")
            )

    def test_staged_proof_publication_is_atomic_and_never_clobbers(self) -> None:
        staging = self.account_home / "proof.pending"
        destination = self.account_home / "proof.json"
        staging.write_bytes(b'{"status":"pass"}\n')
        staging.chmod(0o600)
        android_device_proof.publish_staged_proof(
            argparse.Namespace(staging=staging, destination=destination)
        )
        self.assertFalse(staging.exists())
        self.assertEqual(destination.read_bytes(), b'{"status":"pass"}\n')
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

        second_staging = self.account_home / "second.pending"
        second_staging.write_bytes(b"replacement\n")
        second_staging.chmod(0o600)
        with self.assertRaisesRegex(SystemExit, "destination already exists"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=second_staging, destination=destination)
            )
        self.assertEqual(destination.read_bytes(), b'{"status":"pass"}\n')
        self.assertEqual(second_staging.read_bytes(), b"replacement\n")

    def test_staged_proof_publication_rejects_symlink_or_insecure_mode(self) -> None:
        source = self.account_home / "source"
        source.write_bytes(b"proof\n")
        source.chmod(0o600)
        staging = self.account_home / "proof.pending"
        staging.symlink_to(source)
        destination = self.account_home / "proof.json"
        with self.assertRaisesRegex(SystemExit, "not a regular file"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )
        staging.unlink()
        staging.write_bytes(b"proof\n")
        staging.chmod(0o640)
        with self.assertRaisesRegex(SystemExit, "mode changed"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )
        staging.chmod(0o600)
        extra_link = self.account_home / "proof.extra-link"
        os.link(staging, extra_link)
        with self.assertRaisesRegex(SystemExit, "unexpected hard links"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )


class AndroidDeviceProofProvenanceTests(unittest.TestCase):
    def _run_postinstall_runtime_steps(
        self,
        failing_operation: str | None,
    ) -> tuple[subprocess.CompletedProcess[bytes], list[str], dict[str, bytes]]:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        phase = producer.index("=== Install and run Android runtime smoke ===")
        start = producer.index("ANDROID_APP_INSTALL_CONFIRMED=1", phase)
        end = producer.index("RUNTIME_RESULT_DEADLINE=", start)
        postinstall = producer[start:end]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "proof"
            distribution.mkdir(mode=0o700)
            calls = root / "calls.txt"
            calls.write_text("", encoding="ascii")
            script = f"""
set -eu
umask 077
DIST={shlex.quote(str(distribution))}
CALLS={shlex.quote(str(calls))}
FAIL_OPERATION={shlex.quote(failing_operation or "")}
PYTHON_BIN={shlex.quote(sys.executable)}
python3() {{ "$PYTHON_BIN" "$@"; }}
android_command() {{
    operation=$1
    printf '%s\\n' "$operation" >>"$CALLS"
    if [ "$FAIL_OPERATION" = "$operation" ]; then
        printf 'bounded diagnostic for %s\\n' "$operation" >&2
        case "$operation" in
            device-time) return 17 ;;
            force-stop) return 18 ;;
            start-app) return 19 ;;
        esac
    fi
    if [ "$operation" = device-time ]; then
        printf '1786240000.123\\n' >"$DIST/adb-device-time.txt"
    fi
    return 0
}}
{postinstall}
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            called_operations = calls.read_text(encoding="ascii").splitlines()
            files = {
                path.name: path.read_bytes()
                for path in distribution.iterdir()
                if path.is_file()
            }
            return result, called_operations, files

    def test_postinstall_runtime_steps_fail_with_actionable_diagnostics(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        phase = producer.index("=== Install and run Android runtime smoke ===")
        start = producer.index("ANDROID_APP_INSTALL_CONFIRMED=1", phase)
        end = producer.index("RUNTIME_RESULT_DEADLINE=", start)
        postinstall = producer[start:end]
        self.assertNotIn("\nandroid_command device-time\n", postinstall)
        self.assertNotIn(
            '\nandroid_command force-stop >"$DIST/adb-force-stop.log"\n',
            postinstall,
        )
        self.assertNotIn(
            '\nandroid_command start-app >"$DIST/adb-start.log"\n',
            postinstall,
        )

        expectations = {
            "device-time": (
                ["device-time"],
                "Android runtime device-time capture failed",
                "adb-device-time.err",
            ),
            "force-stop": (
                ["device-time", "force-stop"],
                "Android runtime force-stop failed",
                "adb-force-stop.log",
            ),
            "start-app": (
                ["device-time", "force-stop", "start-app"],
                "Android runtime activity start failed",
                "adb-start.log",
            ),
        }
        for operation, (calls, label, diagnostic_file) in expectations.items():
            with self.subTest(failing_operation=operation):
                result, called_operations, files = self._run_postinstall_runtime_steps(
                    operation
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(called_operations, calls)
                self.assertIn(label.encode("ascii"), result.stderr)
                expected_exit = {
                    "device-time": 17,
                    "force-stop": 18,
                    "start-app": 19,
                }[operation]
                self.assertIn(f"(exit={expected_exit})".encode("ascii"), result.stderr)
                self.assertIn(
                    f"bounded diagnostic for {operation}\n".encode("ascii"),
                    files[diagnostic_file],
                )

        result, called_operations, _files = self._run_postinstall_runtime_steps(None)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(
            called_operations,
            ["device-time", "force-stop", "start-app"],
        )

    def _run_preinstall_observation(
        self,
        outcomes: tuple[str, ...],
        *,
        bounded_remaining_calls: int | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], dict[str, bytes], int, bool]:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        query_start = producer.index("query_package_state() {")
        query_end = producer.index("\n}\n\nobserve_preinstall_package_absence()", query_start)
        query_function = producer[query_start : query_end + len("\n}\n")]
        observe_start = producer.index("observe_preinstall_package_absence() {")
        observe_end = producer.index("\n}\n\nremove_installed_apk_copy()", observe_start)
        observe_function = producer[observe_start : observe_end + len("\n}\n")]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "proof"
            distribution.mkdir(mode=0o700)
            sequence = root / "sequence.txt"
            sequence.write_text("\n".join(outcomes) + "\n", encoding="ascii")
            counter = root / "query-count.txt"
            counter.write_text("0\n", encoding="ascii")
            remaining_counter = root / "remaining-count.txt"
            remaining_counter.write_text("0\n", encoding="ascii")
            install_marker = root / "install-called"
            if bounded_remaining_calls is None:
                remaining_function = "remaining_bounded_timeout() { printf '5\\n'; }"
            else:
                remaining_function = f"""
remaining_bounded_timeout() {{
    remaining_count=$(/bin/cat "$REMAINING_COUNTER")
    remaining_count=$((remaining_count + 1))
    printf '%s\\n' "$remaining_count" >"$REMAINING_COUNTER"
    if [ "$remaining_count" -le {bounded_remaining_calls} ]; then
        printf '1\\n'
        return 0
    fi
    return 1
}}
""".strip()
            script = f"""
set -eu
umask 077
DIST={shlex.quote(str(distribution))}
PACKAGE_OBSERVATION_LOG="$DIST/adb-package-state-observation.log"
PACKAGE=dev.qperiapt.androidsmoke
QUERY_SEQUENCE={shlex.quote(str(sequence))}
QUERY_COUNTER={shlex.quote(str(counter))}
REMAINING_COUNTER={shlex.quote(str(remaining_counter))}
INSTALL_MARKER={shlex.quote(str(install_marker))}
monotonic_deadline() {{ printf '999\\n'; }}
{remaining_function}
sleep() {{ :; }}
android_command() {{
    test "$1" = package-state
    query_count=$(/bin/cat "$QUERY_COUNTER")
    query_count=$((query_count + 1))
    printf '%s\\n' "$query_count" >"$QUERY_COUNTER"
    outcome=$(/usr/bin/sed -n "${{query_count}}p" "$QUERY_SEQUENCE")
    case "$outcome" in
        absent | present) printf '%s\\n' "$outcome"; return 0 ;;
        nonzero) printf 'retryable:query-nonzero\\n'; return 0 ;;
        timeout) printf 'retryable:query-timeout\\n'; return 0 ;;
        structural) printf 'adapter structural failure\\n' >&2; return 2 ;;
        malformed) printf 'retryable:unexpected\\n'; return 0 ;;
        *) printf 'unexpected test sequence exhaustion\\n' >&2; return 2 ;;
    esac
}}
{query_function}
{observe_function}
if observe_preinstall_package_absence; then
    : >"$INSTALL_MARKER"
    exit 0
else
    exit $?
fi
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            files = {
                path.name: path.read_bytes()
                for path in distribution.iterdir()
                if path.is_file()
            }
            query_count = int(counter.read_text(encoding="ascii"))
            return result, files, query_count, install_marker.exists()

    def _run_installed_package_ownership_observation(
        self,
        outcomes: tuple[str, ...],
        *,
        signer_status: int = 0,
        journal_prefix: str | None = None,
        transport_recovery_outcomes: tuple[str, ...] = (),
        boot_owned_emulator: bool = False,
        device_kind_override: str | None = None,
        emulator_started_override: bool | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], dict[str, bytes], int, int]:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        sample_start = producer.index("observe_installed_package_sample() {")
        observe_start = producer.index("observe_owned_installed_package() {")
        observe_end = producer.index("\n}\n\ncleanup_android_app()", observe_start)
        observe_function = producer[sample_start : observe_end + len("\n}\n")]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "proof"
            work = root / "work"
            distribution.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            if journal_prefix is not None:
                (distribution / "adb-package-state-observation.log").write_text(
                    journal_prefix, encoding="ascii"
                )
            sequence = root / "sequence.txt"
            sequence.write_text("\n".join(outcomes) + "\n", encoding="ascii")
            counter = root / "observation-count.txt"
            counter.write_text("0\n", encoding="ascii")
            signer_counter = root / "signer-count.txt"
            signer_counter.write_text("0\n", encoding="ascii")
            recovery_sequence = root / "recovery-sequence.txt"
            recovery_sequence.write_text(
                "\n".join(transport_recovery_outcomes) + "\n", encoding="ascii"
            )
            recovery_counter = root / "recovery-count.txt"
            recovery_counter.write_text("0\n", encoding="ascii")
            if device_kind_override is None:
                device_kind = "emulator" if boot_owned_emulator else "physical"
            else:
                device_kind = device_kind_override
            if device_kind not in {"emulator", "physical"}:
                raise AssertionError("fixture device kind must be emulator or physical")
            emulator_started = (
                boot_owned_emulator
                if emulator_started_override is None
                else emulator_started_override
            )
            script = f"""
set -eu
umask 077
DIST={shlex.quote(str(distribution))}
PACKAGE_OBSERVATION_LOG="$DIST/adb-package-state-observation.log"
WORK={shlex.quote(str(work))}
installed_apk="$WORK/installed-smoke-base.apk"
OBSERVATION_SEQUENCE={shlex.quote(str(sequence))}
OBSERVATION_COUNTER={shlex.quote(str(counter))}
SIGNER_COUNTER={shlex.quote(str(signer_counter))}
RECOVERY_SEQUENCE={shlex.quote(str(recovery_sequence))}
RECOVERY_COUNTER={shlex.quote(str(recovery_counter))}
SIGNER_STATUS={signer_status}
ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED=0
ANDROID_BOOT_AVD={1 if boot_owned_emulator else 0}
DEVICE_KIND={device_kind}
EMULATOR_STARTED={1 if emulator_started else 0}
remaining_bounded_timeout() {{
    observation_count=$(/bin/cat "$OBSERVATION_COUNTER")
    if [ "$observation_count" -lt {len(outcomes)} ]; then
        printf '15\n'
        return 0
    fi
    return 1
}}
sleep() {{ :; }}
remove_installed_apk_copy() {{ rm -f -- "$installed_apk"; }}
verify_observed_installed_apk_signer() {{
    signer_count=$(/bin/cat "$SIGNER_COUNTER")
    signer_count=$((signer_count + 1))
    printf '%s\n' "$signer_count" >"$SIGNER_COUNTER"
    return "$SIGNER_STATUS"
}}
android_command() {{
    operation=$1
    if [ "$operation" = recover-emulator-transport ]; then
        if [ "$#" -ne 3 ] || [ "$2" != "--timeout-seconds" ] || [ "$3" != "15" ]; then
            printf 'malformed recovery argv fixture\n' >&2
            return 2
        fi
        recovery_count=$(/bin/cat "$RECOVERY_COUNTER")
        recovery_count=$((recovery_count + 1))
        printf '%s\n' "$recovery_count" >"$RECOVERY_COUNTER"
        outcome=$(/usr/bin/sed -n "${{recovery_count}}p" "$RECOVERY_SEQUENCE")
        case "$outcome" in
            recovered | race-device | retryable:transport-inconclusive | \
                retryable:registration-failed | retryable:post-state-unavailable)
                printf '%s\n' "$outcome"; return 0 ;;
            structural) printf 'structural fixture\n' >&2; return 2 ;;
            signal129) printf 'signal fixture\n' >&2; return 129 ;;
            signal130) printf 'signal fixture\n' >&2; return 130 ;;
            signal143) printf 'signal fixture\n' >&2; return 143 ;;
            malformed) printf 'retryable:unexpected\n'; return 0 ;;
            multiline) printf 'recovered\nextra\n'; return 0 ;;
            diagnostic) printf 'recovered\n'; printf 'unexpected diagnostic\n' >&2; return 0 ;;
            *) return 2 ;;
        esac
    fi
    test "$operation" = observe-installed-apk
    observation_count=$(/bin/cat "$OBSERVATION_COUNTER")
    observation_count=$((observation_count + 1))
    printf '%s\n' "$observation_count" >"$OBSERVATION_COUNTER"
    outcome=$(/usr/bin/sed -n "${{observation_count}}p" "$OBSERVATION_SEQUENCE")
    case "$outcome" in
        structural) printf 'structural fixture\n' >&2; return 2 ;;
        exact:*) printf 'fixture\n' >"$installed_apk" ;;
    esac
    printf '%s\n' "$outcome"
}}
{observe_function}
if observe_owned_installed_package 999 postinstall 1; then
    observation_status=0
else
    observation_status=$?
fi
printf '%s\n' "$(/bin/cat "$RECOVERY_COUNTER")" >"$DIST/fixture-recovery-count.txt"
printf '%s\n' "$ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED" \
    >"$DIST/fixture-recovery-attempted.txt"
exit "$observation_status"
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            files = {
                path.name: path.read_bytes()
                for path in distribution.iterdir()
                if path.is_file()
            }
            return (
                result,
                files,
                int(counter.read_text(encoding="ascii")),
                int(signer_counter.read_text(encoding="ascii")),
            )

    def _run_cleanup_observation(
        self,
        package_outcomes: tuple[str, ...],
        *,
        ownership_outcomes: tuple[str, ...] = (),
        transport_recovery_outcomes: tuple[str, ...] = (),
        signer_status: int = 0,
        install_confirmed: bool = True,
        uninstall_status: int = 0,
        cleanup_invocations: int = 1,
        remaining_calls_per_invocation: tuple[int, ...] | None = None,
        boot_owned_emulator: bool = False,
        transport_recovery_attempted: bool = False,
    ) -> tuple[
        subprocess.CompletedProcess[bytes], dict[str, bytes], list[str], int, bool
    ]:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        query_start = producer.index("query_package_state() {")
        query_end = producer.index("\n}\n\nobserve_preinstall_package_absence()", query_start)
        query_function = producer[query_start : query_end + len("\n}\n")]
        sample_start = producer.index("observe_installed_package_sample() {")
        sample_end = producer.index("\n}\n\nobserve_owned_installed_package()", sample_start)
        sample_function = producer[sample_start : sample_end + len("\n}\n")]
        recovery_start = producer.index("attempt_owned_emulator_transport_recovery() {")
        recovery_end = producer.index("\n}\n\ncleanup_android_app()", recovery_start)
        recovery_function = producer[recovery_start : recovery_end + len("\n}\n")]
        cleanup_start = producer.index("cleanup_android_app() {")
        cleanup_end = producer.index("\n}\n\ncleanup_unconfirmed_proof()", cleanup_start)
        cleanup_function = producer[cleanup_start : cleanup_end + len("\n}\n")]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "proof"
            distribution.mkdir(mode=0o700)
            sequence = root / "package-sequence.txt"
            sequence.write_text("\n".join(package_outcomes) + "\n", encoding="ascii")
            ownership_sequence = root / "ownership-sequence.txt"
            ownership_sequence.write_text(
                "\n".join(ownership_outcomes) + "\n", encoding="ascii"
            )
            counter = root / "query-count.txt"
            counter.write_text("0\n", encoding="ascii")
            ownership_counter = root / "ownership-count.txt"
            ownership_counter.write_text("0\n", encoding="ascii")
            recovery_sequence = root / "recovery-sequence.txt"
            recovery_sequence.write_text(
                "\n".join(transport_recovery_outcomes) + "\n", encoding="ascii"
            )
            recovery_counter = root / "recovery-count.txt"
            recovery_counter.write_text("0\n", encoding="ascii")
            signer_counter = root / "signer-count.txt"
            signer_counter.write_text("0\n", encoding="ascii")
            work = root / "work"
            work.mkdir(mode=0o700)
            calls = root / "calls.txt"
            calls.write_text("", encoding="ascii")
            remaining_root = root / "remaining"
            remaining_root.mkdir(mode=0o700)
            if remaining_calls_per_invocation is None:
                remaining_function = f"""
remaining_bounded_timeout() {{
    query_count=$(/bin/cat "$QUERY_COUNTER")
    if [ "$query_count" -lt {len(package_outcomes)} ]; then
        printf '5\n'
        return 0
    fi
    return 1
}}
""".strip()
            else:
                if len(remaining_calls_per_invocation) != cleanup_invocations:
                    raise AssertionError(
                        "each cleanup invocation requires one remaining-call limit"
                    )
                limit_cases = "\n".join(
                    f"        {index}) remaining_limit={limit} ;;"
                    for index, limit in enumerate(
                        remaining_calls_per_invocation, start=1
                    )
                )
                for index in range(1, cleanup_invocations + 1):
                    (remaining_root / str(index)).write_text("0\n", encoding="ascii")
                remaining_function = f"""
remaining_bounded_timeout() {{
    remaining_file="$REMAINING_ROOT/$ANDROID_APP_CLEANUP_INVOCATION"
    remaining_count=$(/bin/cat "$remaining_file")
    remaining_count=$((remaining_count + 1))
    printf '%s\n' "$remaining_count" >"$remaining_file"
    case "$ANDROID_APP_CLEANUP_INVOCATION" in
{limit_cases}
        *) return 1 ;;
    esac
    if [ "$remaining_count" -le "$remaining_limit" ]; then
        printf '5\n'
        return 0
    fi
    return 1
}}
""".strip()
            script = f"""
set -eu
umask 077
DIST={shlex.quote(str(distribution))}
PACKAGE_OBSERVATION_LOG="$DIST/adb-package-state-observation.log"
PACKAGE=dev.qperiapt.androidsmoke
PACKAGE_SEQUENCE={shlex.quote(str(sequence))}
OWNERSHIP_SEQUENCE={shlex.quote(str(ownership_sequence))}
RECOVERY_SEQUENCE={shlex.quote(str(recovery_sequence))}
QUERY_COUNTER={shlex.quote(str(counter))}
OWNERSHIP_COUNTER={shlex.quote(str(ownership_counter))}
RECOVERY_COUNTER={shlex.quote(str(recovery_counter))}
SIGNER_COUNTER={shlex.quote(str(signer_counter))}
CALLS={shlex.quote(str(calls))}
REMAINING_ROOT={shlex.quote(str(remaining_root))}
WORK={shlex.quote(str(work))}
installed_apk="$WORK/installed-smoke-base.apk"
ANDROID_APP_CLEANUP_ARMED=1
ANDROID_APP_INSTALL_CONFIRMED={1 if install_confirmed else 0}
ANDROID_APP_CLEANUP_INVOCATION=0
ANDROID_APP_UNINSTALL_REQUESTED=0
ANDROID_EMULATOR_TRANSPORT_RECOVERY_ATTEMPTED={1 if transport_recovery_attempted else 0}
ANDROID_BOOT_AVD={1 if boot_owned_emulator else 0}
DEVICE_KIND={"emulator" if boot_owned_emulator else "physical"}
EMULATOR_STARTED={1 if boot_owned_emulator else 0}
SERIAL_SHA256_PREFIX=0123456789ab
monotonic_deadline() {{ printf '999\n'; }}
{remaining_function}
sleep() {{ :; }}
remove_installed_apk_copy() {{ rm -f -- "$installed_apk"; }}
verify_observed_installed_apk_signer() {{
    signer_count=$(/bin/cat "$SIGNER_COUNTER")
    signer_count=$((signer_count + 1))
    printf '%s\n' "$signer_count" >"$SIGNER_COUNTER"
    return {signer_status}
}}
android_command() {{
    operation=$1
    printf '%s\n' "$operation" >>"$CALLS"
    if [ "$operation" = uninstall-app ]; then
        return {uninstall_status}
    fi
    if [ "$operation" = observe-installed-apk ]; then
        ownership_count=$(/bin/cat "$OWNERSHIP_COUNTER")
        ownership_count=$((ownership_count + 1))
        printf '%s\n' "$ownership_count" >"$OWNERSHIP_COUNTER"
        outcome=$(/usr/bin/sed -n "${{ownership_count}}p" "$OWNERSHIP_SEQUENCE")
        case "$outcome" in
            structural) printf 'structural fixture\n' >&2; return 2 ;;
            exact:*) printf 'fixture\n' >"$installed_apk" ;;
        esac
        printf '%s\n' "$outcome"
        return 0
    fi
    if [ "$operation" = recover-emulator-transport ]; then
        recovery_count=$(/bin/cat "$RECOVERY_COUNTER")
        recovery_count=$((recovery_count + 1))
        printf '%s\n' "$recovery_count" >"$RECOVERY_COUNTER"
        outcome=$(/usr/bin/sed -n "${{recovery_count}}p" "$RECOVERY_SEQUENCE")
        case "$outcome" in
            recovered | race-device | retryable:transport-inconclusive | \
                retryable:registration-failed | retryable:post-state-unavailable)
                printf '%s\n' "$outcome"; return 0 ;;
            structural) printf 'structural fixture\n' >&2; return 2 ;;
            signal129) printf 'signal fixture\n' >&2; return 129 ;;
            malformed) printf 'retryable:unexpected\n'; return 0 ;;
            diagnostic) printf 'recovered\n'; printf 'unexpected diagnostic\n' >&2; return 0 ;;
            *) return 2 ;;
        esac
    fi
    test "$operation" = package-state
    query_count=$(/bin/cat "$QUERY_COUNTER")
    query_count=$((query_count + 1))
    printf '%s\n' "$query_count" >"$QUERY_COUNTER"
    outcome=$(/usr/bin/sed -n "${{query_count}}p" "$PACKAGE_SEQUENCE")
    case "$outcome" in
        absent | present) printf '%s\n' "$outcome"; return 0 ;;
        nonzero) printf 'retryable:query-nonzero\n'; return 0 ;;
        timeout) printf 'retryable:query-timeout\n'; return 0 ;;
        device-unavailable) printf 'retryable:device-unavailable\n'; return 0 ;;
        structural) printf 'adapter structural failure\n' >&2; return 2 ;;
        malformed) printf 'retryable:unexpected\n'; return 0 ;;
        *) return 2 ;;
    esac
}}
{query_function}
{sample_function}
{recovery_function}
{cleanup_function}
cleanup_iteration=0
cleanup_status=0
while [ "$cleanup_iteration" -lt {cleanup_invocations} ]; do
    cleanup_iteration=$((cleanup_iteration + 1))
    if cleanup_android_app; then
        cleanup_status=0
    else
        cleanup_status=$?
    fi
done
exit "$cleanup_status"
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            files = {
                path.name: path.read_bytes()
                for path in distribution.iterdir()
                if path.is_file()
            }
            return (
                result,
                files,
                calls.read_text(encoding="ascii").splitlines(),
                int(signer_counter.read_text(encoding="ascii")),
                (work / "installed-smoke-base.apk").exists(),
            )

    def _run_install_confirmation(
        self, ownership_status: int, *, install_status: int = 0
    ) -> tuple[subprocess.CompletedProcess[bytes], list[str], bool]:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        phase_start = producer.index("if observe_preinstall_package_absence; then")
        phase_end = producer.index("\nif android_command device-time", phase_start)
        install_phase = producer[phase_start:phase_end]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "proof"
            distribution.mkdir(mode=0o700)
            calls = root / "calls.txt"
            calls.write_text("", encoding="ascii")
            confirmed = root / "confirmed"
            script = f"""
set -eu
umask 077
DIST={shlex.quote(str(distribution))}
CALLS={shlex.quote(str(calls))}
CONFIRMED={shlex.quote(str(confirmed))}
ANDROID_APP_CLEANUP_ARMED=0
ANDROID_APP_INSTALL_CONFIRMED=0
observe_preinstall_package_absence() {{ return 0; }}
monotonic_deadline() {{ printf '999\n'; }}
observe_owned_installed_package() {{
    printf 'observe-owned-installed-package\n' >>"$CALLS"
    return {ownership_status}
}}
android_command() {{
    printf '%s\n' "$1" >>"$CALLS"
    if [ "$1" = install-apk ]; then
        return {install_status}
    fi
    return 0
}}
{install_phase}
test "$ANDROID_APP_INSTALL_CONFIRMED" = 1
: >"$CONFIRMED"
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            return (
                result,
                calls.read_text(encoding="ascii").splitlines(),
                confirmed.exists(),
            )

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "QPeriapt Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "test@invalid.local"],
            check=True,
        )
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("clean\n", encoding="utf-8")
        self.core_source = self.root / "crates" / "q-periapt-core" / "src" / "lib.rs"
        self.core_source.parent.mkdir(parents=True)
        self.core_source.write_text(
            'pub const PROOF_INPUT: &str = "original";\n', encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True
        )
        self.commit = android_device_proof.git_commit(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_results_projection_binds_every_android_runtime_summary_field(self) -> None:
        proof = complete_proof_shape()
        manifest = current_results_for_proof(proof)
        self.assertEqual(
            android_device_proof.verify_results_manifest_projection(
                manifest, proof
            ),
            "emulator",
        )

        cases = (
            (("run_id",), "0" * 32, "run_id"),
            (("release_candidate_mode",), False, "release_candidate_mode"),
            (("device", "kind"), "physical", "device_kind"),
            (("device", "abi"), "x86_64", "device_abi"),
            (("device", "page_size"), 4_096, "page_size"),
            (("device", "sdk"), 36, "android_sdk"),
            (("android", "build_tools"), "35.0.0", "build_tools"),
            (("result", "passed_tests"), [], "result"),
        )
        for path, bad_value, message in cases:
            with self.subTest(path=path):
                changed = copy.deepcopy(proof)
                target = changed
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = bad_value
                with self.assertRaisesRegex(SystemExit, message):
                    android_device_proof.verify_results_manifest_projection(
                        manifest, changed
                    )

        changed = copy.deepcopy(proof)
        changed["artifacts"]["aar_sha256"] = "0" * 64
        with self.assertRaisesRegex(SystemExit, "AAR declaration differs"):
            android_device_proof.verify_results_manifest_projection(manifest, changed)

    def test_physical_results_projection_is_independent_and_noncanonical(self) -> None:
        canonical_proof = complete_proof_shape()
        canonical_manifest = current_results_for_proof(canonical_proof)
        physical_proof = complete_proof_shape()
        physical_proof["run_id"] = "d" * 32
        physical_proof["device"].update(
            {
                "kind": "physical",
                "abi": "x86_64",
                "page_size": 4_096,
                "sdk": 37,
                "manufacturer": "Google",
                "model": "Pixel physical fixture",
            }
        )
        physical_proof["emulator_control"] = None
        physical_proof["release_candidate_mode"] = False
        physical_proof["android"]["build_tools"] = "37.0.0-rc1"
        physical_manifest = current_results_for_proof(
            physical_proof,
            results_binding="android_physical_runtime",
        )
        canonical_manifest["android_physical_runtime"] = physical_manifest[
            "android_physical_runtime"
        ]

        self.assertEqual(
            android_device_proof.verify_results_manifest_projection(
                canonical_manifest,
                canonical_proof,
            ),
            "emulator",
        )
        self.assertEqual(
            android_device_proof.verify_results_manifest_projection(
                canonical_manifest,
                physical_proof,
                results_binding="android_physical_runtime",
            ),
            "physical",
        )

        with self.assertRaisesRegex(SystemExit, "selected proof"):
            android_device_proof.verify_results_manifest_projection(
                canonical_manifest,
                physical_proof,
            )
        with self.assertRaisesRegex(SystemExit, "selected proof"):
            android_device_proof.verify_results_manifest_projection(
                canonical_manifest,
                canonical_proof,
                results_binding="android_physical_runtime",
            )

    def test_physical_projection_rejects_kind_status_source_and_aar_swaps(self) -> None:
        proof = complete_proof_shape()
        proof["run_id"] = "e" * 32
        proof["device"]["kind"] = "physical"
        proof["emulator_control"] = None
        proof["release_candidate_mode"] = False
        manifest = current_results_for_proof(
            proof,
            results_binding="android_physical_runtime",
        )
        section = manifest["android_physical_runtime"]
        cases = (
            (
                "status",
                lambda changed: changed["android_physical_runtime"].__setitem__(
                    "current_source_status",
                    "stale_requires_rerun",
                ),
            ),
            (
                "kind",
                lambda changed: changed["android_physical_runtime"].__setitem__(
                    "device_kind",
                    "emulator",
                ),
            ),
            (
                "source",
                lambda changed: changed["android_physical_runtime"].__setitem__(
                    "proof_source_tree_sha256",
                    "0" * 64,
                ),
            ),
            (
                "AAR hash",
                lambda changed: changed["android_aar"].__setitem__(
                    "aar_sha256",
                    "0" * 64,
                ),
            ),
            (
                "AAR path",
                lambda changed: changed["android_aar"].__setitem__(
                    "aar_path",
                    "target/other.aar",
                ),
            ),
        )
        self.assertEqual(section["release_candidate_mode"], False)
        for label, mutate in cases:
            with self.subTest(label=label), self.assertRaises(SystemExit):
                changed = copy.deepcopy(manifest)
                mutate(changed)
                android_device_proof.verify_results_manifest_projection(
                    changed,
                    proof,
                    results_binding="android_physical_runtime",
                )

    def test_manifest_bound_verify_derives_kind_and_rejects_dirty_or_conflict(
        self,
    ) -> None:
        proof = complete_proof_shape()
        manifest_value = current_results_for_proof(proof)
        manifest_snapshot = mock.Mock(value=manifest_value)
        proof_snapshot = mock.Mock(value=proof, file=mock.Mock(sha256="f" * 64))
        proof_path = self.root / manifest_value["android_device_runtime"]["proof_path"]
        arguments = argparse.Namespace(
            root=self.root,
            proof=proof_path,
            results_manifest=self.root / "artifact/results.json",
            expected_results_manifest_sha256="e" * 64,
            results_binding="android_runtime",
            expected_device_kind="",
            expected_device_abi="arm64-v8a",
            expected_page_size=16_384,
            expected_device_sdk=35,
            require_release_mode=True,
            allow_dirty_proof=False,
            max_age_seconds=86_400,
        )
        with (
            mock.patch.object(
                android_device_proof,
                "load_results_manifest_snapshot",
                return_value=manifest_snapshot,
            ),
            mock.patch.object(
                android_device_proof,
                "select_bound_json_snapshot",
                return_value=proof_snapshot,
            ),
            mock.patch.object(android_device_proof, "verify_proof_schema"),
            mock.patch.object(android_device_proof, "verify_proof_freshness"),
            mock.patch.object(
                android_device_proof, "proof_paths", return_value={}
            ),
            mock.patch.object(
                android_device_proof, "validate_selected_run_layout"
            ),
            mock.patch.object(
                android_device_proof, "verify_proof_contents"
            ) as verify_contents,
        ):
            android_device_proof.verify(arguments)
            self.assertEqual(
                verify_contents.call_args.kwargs["expected_device_kind"],
                "emulator",
            )

            arguments.expected_device_kind = "physical"
            with self.assertRaisesRegex(SystemExit, "conflicts"):
                android_device_proof.verify(arguments)

            arguments.expected_device_kind = ""
            arguments.allow_dirty_proof = True
            with self.assertRaisesRegex(SystemExit, "does not allow dirty proofs"):
                android_device_proof.verify(arguments)

    def test_manifest_bound_verify_rejects_a_stale_runtime_status(self) -> None:
        proof = complete_proof_shape()
        manifest = current_results_for_proof(proof)
        manifest["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        with self.assertRaisesRegex(
            SystemExit,
            "requires a current emulator runtime status",
        ):
            android_device_proof.verify_results_manifest_projection(manifest, proof)

    def test_manifest_bound_verify_selects_the_fixed_physical_binding(self) -> None:
        proof = complete_proof_shape()
        proof["run_id"] = "f" * 32
        proof["device"]["kind"] = "physical"
        proof["emulator_control"] = None
        proof["release_candidate_mode"] = False
        manifest_value = current_results_for_proof(
            proof,
            results_binding="android_physical_runtime",
        )
        manifest_snapshot = mock.Mock(value=manifest_value)
        proof_snapshot = mock.Mock(value=proof, file=mock.Mock(sha256="e" * 64))
        proof_path = self.root / manifest_value["android_physical_runtime"][
            "proof_path"
        ]
        arguments = argparse.Namespace(
            root=self.root,
            proof=proof_path,
            results_manifest=self.root / "artifact/results.json",
            expected_results_manifest_sha256="d" * 64,
            results_binding="android_physical_runtime",
            expected_device_kind="",
            expected_device_abi="",
            expected_page_size=None,
            expected_device_sdk=None,
            require_release_mode=False,
            allow_dirty_proof=False,
            max_age_seconds=86_400,
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                android_device_proof,
                "load_results_manifest_snapshot",
                return_value=manifest_snapshot,
            ),
            mock.patch.object(
                android_device_proof,
                "select_bound_json_snapshot",
                return_value=proof_snapshot,
            ) as select_bound,
            mock.patch.object(android_device_proof, "verify_proof_schema"),
            mock.patch.object(android_device_proof, "verify_proof_freshness"),
            mock.patch.object(android_device_proof, "proof_paths", return_value={}),
            mock.patch.object(android_device_proof, "validate_selected_run_layout"),
            mock.patch.object(
                android_device_proof,
                "verify_proof_contents",
            ) as verify_contents,
            contextlib.redirect_stdout(output),
        ):
            android_device_proof.verify(arguments)

        self.assertEqual(
            select_bound.call_args.kwargs["binding"],
            "android_physical_runtime",
        )
        self.assertEqual(
            verify_contents.call_args.kwargs["expected_device_kind"],
            "physical",
        )
        self.assertIn(
            "section=android_physical_runtime",
            output.getvalue(),
        )

    def test_matching_clean_provenance_passes(self) -> None:
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )

    def test_apksigner_output_requires_one_exact_signer_digest(self) -> None:
        digest = "a" * 64
        output = (
            "Signer #1 certificate DN: CN=QPeriapt Android Smoke\n"
            f"Signer #1 certificate SHA-256 digest: {digest}\n"
            "Signer #1 certificate SHA-1 digest: deadbeef\n"
        )
        self.assertEqual(
            android_device_proof.parse_single_signer_sha256(output), digest
        )
        malformed_outputs = (
            "",
            "Signer #1 certificate SHA-256 digest: deadbeef\n",
            (
                f"Signer #1 certificate SHA-256 digest: {digest}\n"
                f"Signer #2 certificate SHA-256 digest: {'b' * 64}\n"
            ),
            f"Signer #2 certificate SHA-256 digest: {digest}\n",
        )
        for malformed in malformed_outputs:
            with self.subTest(output=malformed):
                with self.assertRaisesRegex(
                    SystemExit, "exactly one signer #1 SHA-256"
                ):
                    android_device_proof.parse_single_signer_sha256(malformed)

    def test_allow_dirty_never_bypasses_commit_binding(self) -> None:
        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": "0" * 40, "source_tree_dirty": True},
                allow_dirty_proof=True,
            )

    def test_evidence_only_successor_commit_can_bind_release_proof(self) -> None:
        proof_commit = self.commit
        proof_digest = android_device_proof.current_source_tree_digest(self.root)
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"proof":"bound"}\n', encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "artifact/results.json"], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "bind evidence"], check=True
        )

        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": proof_commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": proof_digest},
        )

    def test_source_changing_successor_commit_is_rejected(self) -> None:
        proof_commit = self.commit
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-qm", "change source"], check=True
        )

        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": proof_commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_strict_verification_rejects_current_dirty_tree(self) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "current source tree is dirty"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": self.commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_diagnostic_verification_allows_dirty_tree_but_keeps_commit_binding(
        self,
    ) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": True},
            allow_dirty_proof=True,
        )

    def test_current_proof_schema_is_required(self) -> None:
        proof = complete_proof_shape()
        wrong_schema = copy.deepcopy(proof)
        wrong_schema["schema"] = 2
        with self.assertRaisesRegex(
            SystemExit,
            f"Android proof schema must be {android_device_proof.PROOF_SCHEMA_VERSION}",
        ):
            android_device_proof.verify_proof_schema(wrong_schema)
        android_device_proof.verify_proof_schema(proof)

        extra_top_level = copy.deepcopy(proof)
        extra_top_level["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof fields differ"):
            android_device_proof.verify_proof_schema(extra_top_level)

        extra_device_field = copy.deepcopy(proof)
        extra_device_field["device"]["serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof device fields differ"):
            android_device_proof.verify_proof_schema(extra_device_field)

        extra_result_field = copy.deepcopy(proof)
        extra_result_field["result"]["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof result fields differ"):
            android_device_proof.verify_proof_schema(extra_result_field)

    def test_emulator_control_is_exact_sanitized_and_port_bound(self) -> None:
        proof = complete_proof_shape()
        android_device_proof.verify_emulator_control(proof, require_release_mode=True)
        dual_stack = copy.deepcopy(proof)
        dual_stack["emulator_control"]["listener_endpoints"].extend(
            ["[::1]:5584", "[::1]:5585"]
        )
        android_device_proof.verify_emulator_control(
            dual_stack, require_release_mode=True
        )
        half_dual_stack = copy.deepcopy(dual_stack)
        half_dual_stack["emulator_control"]["listener_endpoints"].pop()
        with self.assertRaisesRegex(SystemExit, "listener endpoints differ"):
            android_device_proof.verify_emulator_control(half_dual_stack)

        for mutation, expected in (
            ("backend_identity", "backend identity differs"),
            ("backend_digest", "backend lacks a valid SHA-256"),
            ("port_pair", "control ports are invalid"),
            ("process_identity", "listener process identity differs"),
            ("endpoints", "listener endpoints differ"),
            ("registration_enum", "registration response is unsupported"),
            ("registration_digest", "response digest differs"),
            ("private_adb_identity", "process identity lacks a valid SHA-256"),
            ("external_transport", "private transport binding differs"),
            ("native_notifier_port", "native adb notifier contract differs"),
            ("checkpoint_order", "checkpoint order differs"),
            ("extra_raw_field", "control fields differ"),
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(proof)
                control = changed["emulator_control"]
                if mutation == "backend_identity":
                    control["backend"]["identity"] = "qemu-system-x86_64-headless"
                elif mutation == "backend_digest":
                    control["backend"]["sha256"] = "not-a-digest"
                elif mutation == "port_pair":
                    control["ports"]["adb"] = 5587
                elif mutation == "process_identity":
                    control["listener_process_identity_sha256"] = "9" * 64
                elif mutation == "endpoints":
                    control["listener_endpoints"] = [
                        "127.0.0.1:5584",
                        "0.0.0.0:5585",
                    ]
                elif mutation == "registration_enum":
                    control["registration"]["accepted_response"] = "connected-ish"
                elif mutation == "registration_digest":
                    control["registration"]["response_sha256"] = "0" * 64
                elif mutation == "private_adb_identity":
                    control["private_adb"]["identity_sha256"] = None
                elif mutation == "external_transport":
                    control["external_adb"]["transport_binding_sha256"] = "0" * 64
                elif mutation == "native_notifier_port":
                    control["native_notifier"]["port"] = 5037
                elif mutation == "checkpoint_order":
                    control["native_notifier"]["admission_checkpoints"].reverse()
                else:
                    control["home"] = "/Users/example"
                with self.assertRaisesRegex(SystemExit, expected):
                    android_device_proof.verify_emulator_control(changed)

        serialized = android_device_proof.canonical_json(proof["emulator_control"])
        for forbidden in (b"/Users/", b"adbkey", b"adb.sock", b'"pid"', b'"uid"'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)

    def test_registration_enum_commits_to_the_exact_accepted_response(self) -> None:
        for accepted_response in android_device_proof.EMULATOR_REGISTRATION_RESPONSES:
            with self.subTest(accepted_response=accepted_response):
                proof = complete_proof_shape()
                registration = proof["emulator_control"]["registration"]
                registration["accepted_response"] = accepted_response
                response = android_device_proof.emulator_registration_response_bytes(
                    accepted_response,
                    console_port=5584,
                    adb_port=5585,
                )
                registration["response_sha256"] = android_device_proof.sha256_bytes(
                    response
                )
                android_device_proof.verify_emulator_control(proof)

    def test_control_receipt_builder_emits_only_sanitized_commitments(self) -> None:
        run_id = "c" * 32
        proof_root = (
            self.root
            / "target"
            / android_device_proof.ANDROID_RUNS_ROOT_LEAF
            / run_id
            / "proof"
        )
        proof_root.mkdir(parents=True)
        backend = self.root / "qemu-system-aarch64-headless"
        backend.write_bytes(b"fixed headless backend")
        backend.chmod(0o700)
        listener = self.root / "emulator-listeners.txt"
        registration = self.root / "registration.txt"
        private_status = (
            proof_root / android_device_proof.PRIVATE_ADB_STATUS_REGISTERED_LEAF
        )
        private_listener = (
            proof_root / android_device_proof.PRIVATE_ADB_LISTENER_REGISTERED_LEAF
        )
        current_uid = os.geteuid()
        emulator_identity = f"123:{current_uid}:456:789"
        private_adb_identity = f"321:{current_uid}:654:987"
        listener.write_text(
            f"p123\nu{current_uid}\n"
            "f4\nn127.0.0.1:5584\nf5\nn127.0.0.1:5585\n"
            "f6\nn[::1]:5584\nf7\nn[::1]:5585\n",
            encoding="utf-8",
        )
        registration.write_bytes(
            android_device_proof.emulator_registration_response_bytes(
                "connected", console_port=5584, adb_port=5585
            )
        )
        expected_adb = proof_root.parent / "work" / f"adb-{run_id}"
        expected_key = android_device_proof.current_account_home() / ".android" / "adbkey"
        private_status.write_text(
            f'executable_absolute_path: "{expected_adb}"\n'
            f'keystore_path: "{expected_key}"\n'
            "mdns_enabled: false\n",
            encoding="utf-8",
        )
        private_listener.write_text(
            f"p321\nu{current_uid}\nf7\n"
            "n/tmp/qperiapt-adb.A1b2C3d4/adb.sock\n",
            encoding="utf-8",
        )
        private_status.chmod(0o600)
        private_listener.chmod(0o600)
        private_adb = {
            "adb_profile": "macos-account",
            "identity_sha256": android_device_proof.process_identity_sha256(
                private_adb_identity, "private adb process identity"
            ),
            "server_status_sha256": android_device_proof.sha256_file(private_status),
            "listener_snapshot_sha256": android_device_proof.sha256_file(
                private_listener
            ),
            "listener_descriptor_sha256": hashlib.sha256(b"7").hexdigest(),
        }
        routing_receipt, isolation_receipts = write_emulator_isolation_receipts(
            proof_root,
            run_id=run_id,
            private_adb=private_adb,
        )

        receipt = android_device_proof.build_emulator_control_receipt(
            backend_path=backend,
            backend_device=backend.stat().st_dev,
            backend_inode=backend.stat().st_ino,
            backend_sha256=android_device_proof.sha256_file(backend),
            device_abi="arm64-v8a",
            console_port=5584,
            process_identity=emulator_identity,
            listener_snapshot_path=listener,
            registration_response_path=registration,
            private_adb_identity=private_adb_identity,
            private_adb_status_path=private_status,
            private_adb_listener_path=private_listener,
            routing_receipt_path=routing_receipt,
            adb_isolation_receipt_paths=isolation_receipts,
            run_id=run_id,
        )
        proof = complete_proof_shape()
        proof["run_id"] = run_id
        proof["emulator_control"] = receipt
        android_device_proof.verify_emulator_control(proof, require_release_mode=True)
        self.assertEqual(
            receipt["backend"]["sha256"],
            android_device_proof.sha256_file(backend),
        )
        self.assertEqual(
            receipt["registration"]["response_sha256"],
            android_device_proof.sha256_file(registration),
        )
        self.assertEqual(
            receipt["listener_endpoints"],
            [
                "127.0.0.1:5584",
                "127.0.0.1:5585",
                "[::1]:5584",
                "[::1]:5585",
            ],
        )
        serialized = android_device_proof.canonical_json(receipt)
        for raw_value in (
            emulator_identity.encode("ascii"),
            private_adb_identity.encode("ascii"),
            os.fsencode(self.root),
            listener.read_bytes(),
            registration.read_bytes(),
        ):
            with self.subTest(raw_value=raw_value):
                self.assertNotIn(raw_value, serialized)

        run_evidence_paths = {
            android_device_proof.ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[
                checkpoint
            ]: path
            for checkpoint, path in isolation_receipts.items()
        }
        run_evidence_paths["emulator_routing"] = routing_receipt
        android_device_proof.verify_emulator_control_evidence(
            proof, run_evidence_paths
        )
        routing_bytes = routing_receipt.read_bytes()
        prior_routing = json.loads(routing_bytes)
        prior_routing["schema"] = 1
        routing_receipt.write_bytes(android_device_proof.canonical_json(prior_routing))
        try:
            with self.assertRaisesRegex(SystemExit, "routing receipt contract differs"):
                android_device_proof.verify_emulator_control_evidence(
                    proof, run_evidence_paths
                )
        finally:
            routing_receipt.write_bytes(routing_bytes)
            routing_receipt.chmod(0o600)
        malformed_routing = json.loads(routing_bytes)
        malformed_routing["private_adb"]["adb_profile"] = []
        routing_receipt.write_bytes(
            android_device_proof.canonical_json(malformed_routing)
        )
        try:
            with self.assertRaisesRegex(SystemExit, "private adb profile is invalid"):
                android_device_proof.verify_emulator_control_evidence(
                    proof, run_evidence_paths
                )
        finally:
            routing_receipt.write_bytes(routing_bytes)
            routing_receipt.chmod(0o600)
        private_listener_bytes = private_listener.read_bytes()
        private_listener.write_bytes(private_listener_bytes.replace(b"f7\n", b"f8\n"))
        with self.assertRaisesRegex(
            SystemExit,
            "digest-bound listening descriptor|differs from its proof projection",
        ):
            android_device_proof.verify_emulator_control_evidence(
                proof, run_evidence_paths
            )
        private_listener.write_bytes(private_listener_bytes)
        private_listener.chmod(0o600)

        bundled_paths: dict[str, pathlib.Path] = {}
        bundle_evidence = self.root / "bundle-evidence"
        bundle_evidence.mkdir()
        for checkpoint, source in isolation_receipts.items():
            key = android_device_proof.ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[
                checkpoint
            ]
            destination = bundle_evidence / source.name
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
            bundled_paths[key] = destination
        bundled_routing = bundle_evidence / routing_receipt.name
        shutil.copyfile(routing_receipt, bundled_routing)
        bundled_routing.chmod(0o644)
        bundled_paths["emulator_routing"] = bundled_routing
        android_device_proof.verify_emulator_control_evidence(
            proof, bundled_paths, bundled=True
        )

        first_checkpoint = android_device_proof.ADB_ISOLATION_CHECKPOINTS[0]
        first_path = bundled_paths[
            android_device_proof.ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[first_checkpoint]
        ]
        tampered_checkpoint = json.loads(first_path.read_text(encoding="utf-8"))
        tampered_checkpoint["ports"][
            str(android_device_proof.NATIVE_ADB_NOTIFIER_PORT)
        ]["ipv6"] = "timed_out"
        first_path.write_bytes(android_device_proof.canonical_json(tampered_checkpoint))
        with self.assertRaisesRegex(SystemExit, "was not closed"):
            android_device_proof.verify_emulator_control_evidence(
                proof, bundled_paths, bundled=True
            )
        shutil.copyfile(isolation_receipts[first_checkpoint], first_path)
        first_path.chmod(0o644)

        tampered_routing = json.loads(bundled_routing.read_text(encoding="utf-8"))
        tampered_routing["private_adb"]["listener_snapshot_sha256"] = "0" * 64
        bundled_routing.write_bytes(android_device_proof.canonical_json(tampered_routing))
        with self.assertRaisesRegex(SystemExit, "transport binding differs"):
            android_device_proof.verify_emulator_control_evidence(
                proof, bundled_paths, bundled=True
            )

        registration.write_bytes(b"Connected to emulator on ports 5584,5585\r\n")
        with self.assertRaisesRegex(SystemExit, "not an accepted exact value"):
            android_device_proof.build_emulator_control_receipt(
                backend_path=backend,
                backend_device=backend.stat().st_dev,
                backend_inode=backend.stat().st_ino,
                backend_sha256=android_device_proof.sha256_file(backend),
                device_abi="arm64-v8a",
                console_port=5584,
                process_identity=emulator_identity,
                listener_snapshot_path=listener,
                registration_response_path=registration,
                private_adb_identity=private_adb_identity,
                private_adb_status_path=private_status,
                private_adb_listener_path=private_listener,
                routing_receipt_path=routing_receipt,
                adb_isolation_receipt_paths=isolation_receipts,
                run_id=run_id,
            )

    def test_process_identity_commitment_requires_canonical_tuple(self) -> None:
        expected = android_device_proof.sha256_bytes(b"123:501:456:789")
        self.assertEqual(
            android_device_proof.process_identity_sha256(
                "123:501:456:789", "test identity"
            ),
            expected,
        )
        for invalid in (
            "1:501:456:789",
            "0123:501:456:789",
            "123:+501:456:789",
            "123:0501:456:789",
            "123:501:0:789",
            "123:501:456:0789",
            "123:501:456:1000000",
            "2147483648:501:456:789",
            "123:4294967296:456:789",
            "123:501:18446744073709551616:789",
            "123:501:456",
            "123:501:456:789:0",
            "123:501:456:789\n",
            True,
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(SystemExit, "identity"):
                    android_device_proof.process_identity_sha256(
                        invalid, "test identity"
                    )

    def test_physical_proof_requires_explicit_null_emulator_control(self) -> None:
        proof = complete_proof_shape()
        proof["device"]["kind"] = "physical"
        proof["emulator_control"] = None
        proof["paths"] = {
            key: proof["paths"][key]
            for key in android_device_proof.BASE_PROOF_PATH_KEYS
        }
        android_device_proof.verify_proof_schema(proof)

        proof["emulator_control"] = complete_proof_shape()["emulator_control"]
        with self.assertRaisesRegex(SystemExit, "must set emulator_control to null"):
            android_device_proof.verify_proof_schema(proof)

        emulator = complete_proof_shape()
        emulator["emulator_control"] = None
        with self.assertRaisesRegex(
            SystemExit, "Android emulator control fields differ"
        ):
            android_device_proof.verify_proof_schema(emulator)

    def test_release_emulator_control_requires_reserved_high_port_pair(self) -> None:
        proof = complete_proof_shape()
        control = proof["emulator_control"]
        control["ports"] = {"console": 5554, "adb": 5555}
        control["listener_endpoints"] = ["127.0.0.1:5554", "127.0.0.1:5555"]
        response = android_device_proof.emulator_registration_response_bytes(
            "connected", console_port=5554, adb_port=5555
        )
        control["registration"]["response_sha256"] = android_device_proof.sha256_bytes(
            response
        )
        android_device_proof.verify_emulator_control(proof)
        with self.assertRaisesRegex(SystemExit, "must bind emulator ports 5584/5585"):
            android_device_proof.verify_emulator_control(
                proof, require_release_mode=True
            )

    def test_freshness_gate_is_separate_from_timeless_schema_validation(self) -> None:
        proof = complete_proof_shape()
        android_device_proof.verify_proof_schema(proof)
        generated_at = dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc)
        proof["generated_at"] = generated_at.isoformat().replace("+00:00", "Z")
        android_device_proof.verify_proof_freshness(
            proof,
            86400,
            reference_time=generated_at + dt.timedelta(hours=23),
        )
        with self.assertRaisesRegex(SystemExit, "Android proof is stale"):
            android_device_proof.verify_proof_freshness(
                proof,
                86400,
                reference_time=generated_at + dt.timedelta(days=8),
            )

    def test_verify_bundle_cli_is_timeless_but_bundle_creation_has_freshness_gate(
        self,
    ) -> None:
        parser = android_device_proof.build_parser()
        bundle_args = parser.parse_args(
            [
                "verify-bundle",
                "--root",
                ".",
                "--bundle",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertFalse(hasattr(bundle_args, "max_age_seconds"))
        create_args = parser.parse_args(
            [
                "create-bundle",
                "--root",
                ".",
                "--proof",
                "proof.json",
                "--output",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertEqual(create_args.max_age_seconds, 86400)

    def test_release_device_metadata_requires_exact_16k_abi_bound_proof(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )

    def test_device_kind_matches_explicit_expectation(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        for actual_kind, other_kind in (
            ("emulator", "physical"),
            ("physical", "emulator"),
        ):
            with self.subTest(actual_kind=actual_kind):
                proof["device"]["kind"] = actual_kind
                android_device_proof.verify_device_metadata(
                    proof,
                    expected_device_kind=actual_kind,
                    expected_device_abi="arm64-v8a",
                    expected_page_size=16384,
                    expected_device_sdk=35,
                    require_release_mode=True,
                )
                with self.assertRaisesRegex(
                    SystemExit,
                    re.escape(
                        f"expected Android device kind {other_kind}, got {actual_kind}"
                    ),
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_kind=other_kind,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=35,
                        require_release_mode=True,
                    )

    def test_release_device_metadata_rejects_4k_device(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 4096,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        with self.assertRaisesRegex(SystemExit, "expected Android page size 16384"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    @staticmethod
    def physical_release_device_proof() -> dict:
        return {
            "release_candidate_mode": True,
            "device": {
                "kind": "physical",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "samsung",
                "model": "SM-S948U",
                "abi": "arm64-v8a",
                "page_size": 4096,
                "sdk": 36,
                "release": "16",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }

    def test_release_physical_device_keeps_its_own_page_size_and_sdk(self) -> None:
        proof = self.physical_release_device_proof()
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_kind="physical",
            expected_device_abi="arm64-v8a",
            expected_page_size=None,
            expected_device_sdk=None,
            require_release_mode=True,
        )

    def test_release_physical_device_still_requires_release_capture(self) -> None:
        proof = self.physical_release_device_proof()
        proof["release_candidate_mode"] = False
        with self.assertRaisesRegex(
            SystemExit, "not generated in Android release-candidate mode"
        ):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_kind="physical",
                expected_device_abi="arm64-v8a",
                expected_page_size=None,
                expected_device_sdk=None,
                require_release_mode=True,
            )

    def test_release_physical_device_still_requires_explicit_abi(self) -> None:
        proof = self.physical_release_device_proof()
        with self.assertRaisesRegex(
            SystemExit, "explicit expected Android device ABI"
        ):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_kind="physical",
                expected_page_size=None,
                expected_device_sdk=None,
                require_release_mode=True,
            )

    def test_device_sdk_is_an_exact_integer_and_matches_expectation(self) -> None:
        proof = {
            "release_candidate_mode": False,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(proof, expected_device_sdk=35)
        for invalid in (None, True, "35", 35.0):
            with self.subTest(invalid=invalid):
                proof["device"]["sdk"] = invalid
                with self.assertRaisesRegex(SystemExit, "invalid Android device SDK"):
                    android_device_proof.verify_device_metadata(
                        proof, expected_device_sdk=35
                    )
        proof["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "expected Android device SDK 35"):
            android_device_proof.verify_device_metadata(proof, expected_device_sdk=35)

    def test_release_requires_expected_device_and_target_sdk_35(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        for expected_sdk in (None, 34):
            with self.subTest(expected_sdk=expected_sdk):
                with self.assertRaisesRegex(
                    SystemExit,
                    "release verification requires expected Android device SDK 35",
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=expected_sdk,
                        require_release_mode=True,
                    )
        proof["android"]["platform"] = "android-34"
        proof["android"]["target_sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "not built against SDK 35"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    def test_release_toolchain_metadata_is_exact_and_bound_to_ndk_tools(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )
        proof["android"]["ndk"] = "29.1.0"
        with self.assertRaisesRegex(SystemExit, "must use NDK 29.0.14206865"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )
        proof["android"]["ndk"] = "29.0.14206865"
        proof["android"]["build_tools"] = "35.0.0"
        with self.assertRaisesRegex(SystemExit, "must use build-tools 36.0.0"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )
        proof["android"]["build_tools"] = "not-a-version"
        with self.assertRaisesRegex(SystemExit, "invalid build-tools metadata"):
            android_device_proof.verify_device_metadata(proof)
        proof["android"]["build_tools"] = "36.0.0"
        proof["android"]["adb_version"] = "adb 1.0.41\nsecret"
        with self.assertRaisesRegex(SystemExit, "invalid adb version metadata"):
            android_device_proof.verify_device_metadata(proof)

        ndk = self.root / "ndk" / "29.0.14206865"
        bin_directory = (
            ndk / "toolchains" / "llvm" / "prebuilt" / "darwin-aarch64" / "bin"
        )
        bin_directory.mkdir(parents=True)
        (ndk / "source.properties").write_text(
            "Pkg.Revision = 29.0.14206865\n", encoding="utf-8"
        )
        llvm_nm = bin_directory / "llvm-nm"
        llvm_readelf = bin_directory / "llvm-readelf"
        for tool in (llvm_nm, llvm_readelf):
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
        resolved_nm, resolved_readelf, revision = (
            android_device_proof.verified_ndk_tools(llvm_nm, llvm_readelf)
        )
        self.assertEqual(resolved_nm, llvm_nm.resolve(strict=True))
        self.assertEqual(resolved_readelf, llvm_readelf.resolve(strict=True))
        self.assertEqual(revision, "29.0.14206865")

    def test_device_sdk_cli_type_is_canonical_and_bounded(self) -> None:
        self.assertEqual(android_device_proof.validate_device_sdk("35"), 35)
        for invalid in ("0", "+35", "035", "35.0", "1000"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    argparse.ArgumentTypeError, "canonical integer between 1 and 999"
                ):
                    android_device_proof.validate_device_sdk(invalid)

    def test_matching_canonical_source_tree_digest_passes(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": digest},
        )

    def test_missing_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            SystemExit, "lacks a valid proof_source_tree_sha256"
        ):
            android_device_proof.verify_source_tree_digest(self.root, {})

    def test_tampered_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": "0" * 64},
            )

    def test_core_change_invalidates_dirty_diagnostic_proof(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        self.core_source.write_text(
            'pub const PROOF_INPUT: &str = "changed";\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": digest},
            )

    def test_ignored_target_proof_does_not_create_a_self_hash_loop(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        proof_output = self.root / "target" / "android" / "proof.json"
        proof_output.parent.mkdir(parents=True)
        proof_output.write_text(
            '{"proof_source_tree_sha256":"placeholder"}\n', encoding="utf-8"
        )
        self.assertEqual(
            digest, android_device_proof.current_source_tree_digest(self.root)
        )

    def test_expected_runtime_inventory_uses_atomic_policy_decision(self) -> None:
        self.assertIn(
            "signedPolicyDecisionIsExactAndFailClosed",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertNotIn(
            "combineReferenceVectors",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertEqual(len(android_device_proof.EXPECTED_TESTS), 3)

    def test_producer_and_verifier_source_input_inventories_match(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        match = re.search(r"source_paths = \{\n(?P<body>.*?)\n\}", producer, re.DOTALL)
        self.assertIsNotNone(match)
        entries = dict(
            re.findall(
                r'^    "([^"]+)": root / "([^"]+)",$', match.group("body"), re.MULTILINE
            )
        )
        self.assertEqual(entries, android_device_proof.SOURCE_INPUTS)

    def test_android_control_dependency_direction_and_source_binding_are_explicit(
        self,
    ) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        bounded = (artifact / "android_bounded_command.py").read_text(encoding="utf-8")
        runtime_state = (artifact / "android_runtime_state.py").read_text(
            encoding="utf-8"
        )
        verifier = (artifact / "android_device_proof.py").read_text(encoding="utf-8")
        control = (artifact / "android_emulator_control.py").read_text(encoding="utf-8")
        process = (artifact / "process_identity.py").read_text(encoding="utf-8")
        self.assertNotIn("from android_device_proof import", bounded)
        self.assertIn("import android_runtime_state as runtime_state", bounded)
        self.assertIn("from android_emulator_control import", bounded)
        self.assertIn("from android_emulator_control import", verifier)
        self.assertIn("import android_runtime_state as runtime_state", verifier)
        self.assertIn("from process_identity import", bounded)
        self.assertIn("from process_identity import", verifier)
        self.assertIn("from android_emulator_control import", runtime_state)
        self.assertIn("from process_identity import", runtime_state)
        self.assertNotIn("android_bounded_command", runtime_state)
        self.assertNotIn("android_device_proof", runtime_state)
        self.assertNotIn("import subprocess", runtime_state)
        self.assertNotIn("import socket", runtime_state)
        for lower_source in (control, process):
            self.assertNotIn("android_bounded_command", lower_source)
            self.assertNotIn("android_device_proof", lower_source)
        self.assertEqual(
            android_device_proof.SOURCE_INPUTS["android_emulator_control"],
            "artifact/android_emulator_control.py",
        )
        self.assertEqual(
            android_device_proof.SOURCE_INPUTS["process_identity"],
            "artifact/process_identity.py",
        )
        self.assertEqual(
            android_device_proof.SOURCE_INPUTS["android_runtime_state"],
            "artifact/android_runtime_state.py",
        )
        self.assertEqual(
            android_device_proof.SOURCE_INPUTS["android_runtime_state_tests"],
            "artifact/test_android_runtime_state.py",
        )
        self.assertEqual(
            {
                key: proof_to_byte_inputs.PROOF_TO_BYTE_INPUT_PATHS.get(key)
                for key in (
                    "android_emulator_control_sha256",
                    "process_identity_sha256",
                    "android_runtime_state_sha256",
                    "android_runtime_state_tests_sha256",
                )
            },
            {
                "android_emulator_control_sha256": (
                    "artifact/android_emulator_control.py"
                ),
                "process_identity_sha256": "artifact/process_identity.py",
                "android_runtime_state_sha256": "artifact/android_runtime_state.py",
                "android_runtime_state_tests_sha256": (
                    "artifact/test_android_runtime_state.py"
                ),
            },
        )

    def test_producer_runs_independent_verifier_before_pass_marker(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        verify = producer.index("artifact/android_device_proof.py verify")
        bundle = producer.index("artifact/android_device_proof.py create-bundle")
        pass_marker = producer.index("ANDROID_DEVICE_RUNTIME_PASS")
        self.assertLess(verify, pass_marker)
        self.assertLess(verify, bundle)
        self.assertLess(bundle, pass_marker)
        self.assertIn("QPERIAPT_ANDROID_EXPECT_SDK=35", producer)
        self.assertIn('"sdk": device_sdk', producer)
        self.assertIn('--expected-device-sdk "$DEVICE_SDK"', producer)

    def test_temporary_keystore_is_private_and_cleaned_on_every_exit(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        lane_lock = producer.index("fcntl.LOCK_EX | fcntl.LOCK_NB")
        run_creation = producer.index('create-run --run-id "$RUN_ID"')
        self.assertLess(lane_lock, run_creation)
        self.assertIn(
            "artifact/android_bounded_command.py lane-lock-path", producer[:lane_lock]
        )
        self.assertIn('exec 9<>"$LANE_LOCK_PATH"', producer[:lane_lock])
        self.assertNotIn('exec 9<"$ROOT', producer)
        self.assertIn("metadata.st_ino) != (path_metadata.st_dev", producer[:lane_lock])
        self.assertIn("umask 077", producer)
        self.assertNotIn('rm -rf "$OUT_ROOT"', producer)
        self.assertIn(
            'OUT_ROOT="$ROOT/target/qperiapt-android-device-smoke-runs/$RUN_ID"',
            producer,
        )
        keystore_assignment = producer.index(
            'KEYSTORE="$WORK/qperiapt-android-smoke.p12"'
        )
        exit_trap = producer.index("trap cleanup_exit EXIT")
        keytool = producer.index("keytool -genkeypair")
        signer = producer.index('"$APKSIGNER" sign')
        eager_removal = producer.index('rm -f -- "$KEYSTORE"', signer)
        self.assertLess(keystore_assignment, exit_trap)
        self.assertLess(exit_trap, keytool)
        self.assertLess(keytool, eager_removal)
        self.assertIn('rm -f -- "$KEYSTORE"', producer[keystore_assignment:keytool])
        self.assertIn("stop_emulator_process()", producer)

    def test_release_emulator_override_fails_before_run_or_process_boundaries(
        self,
    ) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        assignment = producer.index(
            'EMULATOR=${QPERIAPT_EMULATOR:-"$ANDROID_SDK/emulator/emulator"}'
        )
        fragment_end = producer.index('if [ ! -x "$ADB" ]; then', assignment)
        fragment = producer[assignment:fragment_end] + "printf '%s\\n' \"$EMULATOR\"\n"

        def invoke(
            release_mode: str,
            emulator_override: str | None,
        ) -> subprocess.CompletedProcess[str]:
            environment = {
                "ANDROID_RELEASE_MODE": release_mode,
                "ANDROID_SDK": "/fixture/android-sdk",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            }
            if emulator_override is not None:
                environment["QPERIAPT_EMULATOR"] = emulator_override
            return subprocess.run(
                ["/bin/sh", "-eu", "-c", fragment],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )

        rejected = invoke(
            "1",
            "/fixture/android-sdk/emulator/emulator",
        )
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertEqual(rejected.stdout, "")
        self.assertEqual(
            rejected.stderr,
            "error: Android release mode does not allow an emulator executable override\n",
        )

        diagnostic = invoke("0", "/fixture/diagnostic-emulator")
        self.assertEqual(diagnostic.returncode, 0, diagnostic.stderr)
        self.assertEqual(diagnostic.stdout, "/fixture/diagnostic-emulator\n")
        self.assertEqual(diagnostic.stderr, "")

        release_default = invoke("1", None)
        self.assertEqual(release_default.returncode, 0, release_default.stderr)
        self.assertEqual(
            release_default.stdout,
            "/fixture/android-sdk/emulator/emulator\n",
        )
        self.assertEqual(release_default.stderr, "")

        override_guard = producer.index(
            'if [ "$ANDROID_RELEASE_MODE" = "1" ] && '
            '[ "${QPERIAPT_EMULATOR+x}" = x ]; then',
            assignment,
        )
        run_creation = producer.index('create-run --run-id "$RUN_ID"')
        emulator_launch = producer.index("emulator-nodaemon", run_creation)
        self.assertLess(override_guard, run_creation)
        self.assertLess(override_guard, emulator_launch)

    @unittest.skipUnless(os.name == "posix", "repository flock requires POSIX")
    def test_account_lane_lock_survives_atomic_script_replacement(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        lock_start = producer.index("LANE_LOCK_PATH=$(PYTHONPATH=artifact python3")
        lock_end = producer.index("\nfi\n", lock_start) + len("\nfi\n")
        lock_fragment = producer[lock_start:lock_end]

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            script = artifact / "android-device-smoke.sh"
            ready = root / "lock-ready"
            lane_lock = root / "lane.lock"
            lane_lock.write_bytes(b"")
            lane_lock.chmod(0o600)
            wrapper = f"""#!/bin/sh
set -eu
ROOT=$1
python3() {{
    if [ "$#" -eq 2 ] && \
        [ "$1" = "artifact/android_bounded_command.py" ] && \
        [ "$2" = "lane-lock-path" ]; then
        printf '%s\\n' "$TEST_LOCK_PATH"
        return 0
    fi
    "$TEST_PYTHON" "$@"
}}
{lock_fragment}
: > "$LOCK_READY_PATH"
if [ "${{HOLD_LOCK:-0}}" = "1" ]; then
    trap 'exit 0' HUP INT TERM
    while :
    do
        /bin/sleep 1
    done
fi
"""
            script.write_text(wrapper, encoding="utf-8")
            script.chmod(0o700)
            environment = dict(os.environ)
            environment.update(
                {
                    "HOLD_LOCK": "1",
                    "LOCK_READY_PATH": str(ready),
                    "TEST_LOCK_PATH": str(lane_lock),
                    "TEST_PYTHON": sys.executable,
                }
            )
            holder = subprocess.Popen(
                ["/bin/sh", str(script), str(root)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and holder.poll() is None:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.02)
                if not ready.exists():
                    stdout, stderr = holder.communicate(timeout=2)
                    self.fail(
                        "lock holder did not reach its ready point: "
                        f"returncode={holder.returncode} stdout={stdout!r} stderr={stderr!r}"
                    )

                first_inode = script.stat().st_ino
                replacement = artifact / ".android-device-smoke.sh.replacement"
                replacement.write_text(wrapper, encoding="utf-8")
                replacement.chmod(0o700)
                os.replace(replacement, script)
                self.assertNotEqual(script.stat().st_ino, first_inode)

                contender_environment = dict(environment)
                contender_environment["HOLD_LOCK"] = "0"
                contender = subprocess.run(
                    ["/bin/sh", str(script), str(root)],
                    env=contender_environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(contender.returncode, 2, contender.stderr)
                self.assertEqual(contender.stdout, "")
                self.assertIn(
                    "error: another Android evidence lane is already running\n",
                    contender.stderr,
                )
                self.assertTrue(
                    contender.stderr.endswith(
                        "error: cannot acquire the Android evidence lane lock\n"
                    )
                )
            finally:
                if holder.poll() is None:
                    holder.terminate()
                try:
                    holder.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    holder.communicate(timeout=5)

            released_environment = dict(environment)
            released_environment["HOLD_LOCK"] = "0"
            released = subprocess.run(
                ["/bin/sh", str(script), str(root)],
                env=released_environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertEqual(released.returncode, 0, released.stderr)
            self.assertEqual(released.stdout, "")
            self.assertEqual(released.stderr, "")

    def test_android_runtime_documentation_requires_explicit_run_selectors(
        self,
    ) -> None:
        repository_root = pathlib.Path(__file__).resolve().parent.parent
        artifact_document = (repository_root / "ARTIFACT.md").read_text(
            encoding="utf-8"
        )
        android_readme = (repository_root / "bindings/android/README.md").read_text(
            encoding="utf-8"
        )
        embedding_document = (
            repository_root / "docs/EMBEDDING_READINESS.md"
        ).read_text(encoding="utf-8")
        producer = (repository_root / "artifact/android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        embedding_gate = (
            repository_root / "artifact/embedding-readiness.sh"
        ).read_text(encoding="utf-8")
        normalized_artifact_document = " ".join(artifact_document.split())
        self.assertIn(
            "Console replies are parsed as fixed, line-delimited terminal frames",
            normalized_artifact_document,
        )
        self.assertIn(
            "completes the command without waiting for socket EOF",
            normalized_artifact_document,
        )

        unique_proof = (
            "QPERIAPT_ANDROID_DEVICE_PROOF="
            "target/qperiapt-android-device-smoke-runs/<run-id>/proof/"
            "qperiapt-android-device-proof.json"
        )
        for label, source in (
            ("artifact contract", artifact_document),
            ("Android README", android_readme),
            ("embedding guide", embedding_document),
        ):
            with self.subTest(label=label):
                self.assertIn(unique_proof, source)
                self.assertIn("QPERIAPT_ANDROID_EXPECT_ABI=arm64-v8a", source)
        for label, source in (
            ("Android README", android_readme),
            ("embedding guide", embedding_document),
        ):
            with self.subTest(avd_provisioning_document=label):
                self.assertIn("runtime-avd-name", source)
                self.assertIn("umask 077", source)
                self.assertNotIn("QPERIAPT_ANDROID_AVD=", source)

        for label, source, marker in (
            (
                "Android README",
                android_readme,
                "The canonical Android release proof",
            ),
            (
                "embedding guide",
                embedding_document,
                "The canonical Android release runtime",
            ),
        ):
            with self.subTest(fail_fast_document=label):
                marker_index = source.index(marker)
                block_start = source.index("```sh\n", marker_index) + len("```sh\n")
                block_end = source.index("\n```", block_start)
                block_lines = source[block_start:block_end].splitlines()
                self.assertEqual(block_lines[:2], ["(", "set -eu"])
                self.assertEqual(block_lines[-1], ")")
                self.assertLess(
                    source.index("sh artifact/android-aar.sh", block_start),
                    block_end,
                )
                parsed = subprocess.run(
                    ["/bin/sh", "-n"],
                    input=source[block_start:block_end],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(parsed.returncode, 0, parsed.stderr)

        for label, source in (
            ("artifact contract", artifact_document),
            ("embedding guide", embedding_document),
        ):
            with self.subTest(selector_document=label):
                self.assertIn(
                    "QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1",
                    source,
                )
                self.assertIn(
                    "QPERIAPT_ANDROID_RUNTIME_RUN=<32-hex-run-id>",
                    source,
                )

        self.assertIn("Current proof schema v6", android_readme)
        self.assertIn("historical published receipt remains schema v3", android_readme)
        self.assertIn("raw-value-omitting, source-bound", artifact_document)
        self.assertIn("raw-value-omitting, source-bound", embedding_document)
        self.assertIn(
            "QPERIAPT_ANDROID_EXPECT_ABI=<abi>",
            producer,
        )
        self.assertIn(
            "QPERIAPT_ANDROID_DEVICE_PROOF=<reported immutable proof path>",
            embedding_gate,
        )
        self.assertIn("emulator_cleanup_deadline=$(monotonic_deadline 20)", producer)
        self.assertNotIn('kill -TERM "$EMULATOR_PID"', producer)
        self.assertNotIn('kill -KILL "$EMULATOR_PID"', producer)
        self.assertNotIn('kill -TERM "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertNotIn('kill -KILL "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertNotIn("|| :", producer)
        self.assertNotIn("|| true", producer)
        self.assertNotIn(
            "qperiapt-android-smoke.p12",
            "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values()),
        )

    def test_pre_receipt_exit_cleanup_removes_only_exact_empty_private_adb_directory(
        self,
    ) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        start = producer.index("stop_private_adb_server() {")
        end = producer.index(
            "\n}\n\ncleanup_android_command_capability()", start
        ) + len("\n}\n")
        function = producer[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary) / "qperiapt-adb.ABCDEFGH"
            directory.mkdir(mode=0o700)
            socket_path = directory / "adb.sock"
            script = (
                "set -eu\n"
                + function
                + "\nADB_PRIVATE_SERVER_CLEANUP_ARMED=1\n"
                + f"ADB_PRIVATE_SERVER_DIRECTORY={shlex.quote(str(directory))}\n"
                + f"ADB_PRIVATE_SERVER_SOCKET_PATH={shlex.quote(str(socket_path))}\n"
                + "ADB_PRIVATE_SERVER_SOCKET_SPEC=localfilesystem:test\n"
                + "ADB_PRIVATE_SERVER_PID=\n"
                + "ANDROID_RUNTIME_RECOVERY_ARMED=0\n"
                + "RUN_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                + "stop_private_adb_server\n"
                + 'test ! -e "$ADB_PRIVATE_SERVER_DIRECTORY"\n'
            )
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))

    def test_temporary_app_and_booted_avd_are_bound_and_cleaned(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        trap_index = producer.index("trap cleanup_exit EXIT")
        preflight_index = producer.index(
            "if observe_preinstall_package_absence; then", trap_index
        )
        armed_index = producer.index("ANDROID_APP_CLEANUP_ARMED=1", preflight_index)
        install_index = producer.index("android_command install-apk", armed_index)
        normal_cleanup_index = producer.index(
            "if cleanup_android_app; then", install_index
        )
        cleanup_index = producer.index(
            'if [ "${ANDROID_APP_CLEANUP_ARMED:-0}" = "1" ]; then'
        )
        emulator_cleanup_index = producer.index(
            'if [ "${EMULATOR_STARTED:-0}" = "1" ]', cleanup_index
        )
        boot_loop_index = producer.index(
            "EMULATOR_ADB_DEADLINE=$(monotonic_deadline 90)"
        )
        child_liveness_index = producer.index(
            "if ! emulator_process_active; then", boot_loop_index
        )
        bound_serial_index = producer.index(
            "android_command device-state", boot_loop_index
        )
        self.assertLess(producer.index("ANDROID_APP_CLEANUP_ARMED=0"), trap_index)
        self.assertLess(trap_index, preflight_index)
        self.assertLess(preflight_index, armed_index)
        self.assertLess(armed_index, install_index)
        self.assertLess(install_index, normal_cleanup_index)
        self.assertLess(cleanup_index, emulator_cleanup_index)
        self.assertLess(child_liveness_index, bound_serial_index)
        self.assertIn("adb-uninstall-cleanup.log", producer)
        self.assertIn(
            "app_cleanup_status=$?",
            producer[cleanup_index:emulator_cleanup_index],
        )
        self.assertIn(
            'record_runtime_cleanup_failure "$app_cleanup_status"',
            producer[cleanup_index:emulator_cleanup_index],
        )
        self.assertNotIn("\n\tcleanup_status=", producer)
        self.assertNotIn("\n\towned_process_recorded=", producer)
        self.assertNotIn("\n\tprocess_stopped=", producer)
        runtime_function_start = producer.index("cleanup_runtime()")
        runtime_function_end = producer.index(
            "cleanup_runtime_with_deferred_signals()", runtime_function_start
        )
        runtime_function = producer[runtime_function_start:runtime_function_end]
        private_cleanup = runtime_function.index("stop_private_adb_server")
        unresolved_guard = runtime_function.index(
            'if [ "${ADB_PRIVATE_SERVER_CLEANUP_ARMED:-0}" = "1" ]',
            private_cleanup,
        )
        capability_cleanup = runtime_function.index(
            "cleanup_android_command_capability", unresolved_guard
        )
        self.assertLess(private_cleanup, unresolved_guard)
        self.assertLess(unresolved_guard, capability_cleanup)
        self.assertIn(
            "preserving the Android command capability because private adb cleanup is unresolved",
            runtime_function,
        )
        self.assertIn(
            "retirement_exit_status=$primary_exit_status",
            runtime_function,
        )
        self.assertIn(
            'retirement_exit_status=$runtime_internal_cleanup_status',
            runtime_function,
        )
        self.assertIn("retire-stopped-runtime --run-id", runtime_function)
        self.assertIn("retire-failed-runtime --run-id", runtime_function)
        self.assertIn(
            '--primary-exit-status "$retirement_exit_status"',
            runtime_function,
        )
        cleanup_exit_start = producer.index("cleanup_exit()")
        cleanup_exit_end = producer.index(
            "ANDROID_APP_CLEANUP_ARMED=0", cleanup_exit_start
        )
        cleanup_exit = producer[cleanup_exit_start:cleanup_exit_end]
        self.assertIn('cleanup_runtime "$exit_status"', cleanup_exit)
        self.assertIn(
            'elif [ "$exit_status" -eq 0 ] && [ "$exit_runtime_cleanup_status" -ne 0 ]; then',
            cleanup_exit,
        )
        verifier_start = producer.index("verify_observed_installed_apk_signer()")
        verifier_end = producer.index("cleanup_android_app()", verifier_start)
        verifier = producer[verifier_start:verifier_end]
        self.assertLess(
            verifier.index('installed_apk_identity" != "$SIGNED_APK_IDENTITY'),
            verifier.index('installed_signer_sha256" != "$EXPECTED_APK_SIGNER_SHA256'),
        )
        cleanup_start = verifier_end
        cleanup_end = producer.index("cleanup_runtime()", cleanup_start)
        cleanup = producer[cleanup_start:cleanup_end]
        journal_initialization = producer.index(
            'if ! : >"$PACKAGE_OBSERVATION_LOG"', trap_index
        )
        self.assertLess(journal_initialization, preflight_index)
        self.assertEqual(producer.count(': >"$PACKAGE_OBSERVATION_LOG"'), 1)
        self.assertNotIn(': >"$PACKAGE_OBSERVATION_LOG"', cleanup)
        self.assertIn('>>"$PACKAGE_OBSERVATION_LOG"', cleanup)
        threshold = cleanup.index(
            'if [ "$absent_observations" -ge "$required_absent_observations" ]'
        )
        disarm = cleanup.index("ANDROID_APP_CLEANUP_ARMED=0", threshold)
        present = cleanup.index("present)")
        sample_gate = cleanup.index("observe_installed_package_sample", present)
        same_path_gate = cleanup.index(
            '"$OWNERSHIP_SAMPLE_PATH_SHA256" =', sample_gate
        )
        signer_gate = cleanup.index("verify_observed_installed_apk_signer", same_path_gate)
        owned_uninstall = cleanup.index("android_command uninstall-app", signer_gate)
        unknown_outcome = cleanup.index("uninstall=unknown-or-failed", owned_uninstall)
        self.assertLess(threshold, disarm)
        self.assertLess(present, sample_gate)
        self.assertLess(sample_gate, same_path_gate)
        self.assertLess(same_path_gate, signer_gate)
        self.assertLess(signer_gate, owned_uninstall)
        self.assertLess(owned_uninstall, unknown_outcome)
        self.assertNotIn('install -r "$SIGNED_APK"', producer)
        self.assertNotIn("logcat -c", producer)
        self.assertNotIn("android_command package-list", producer)
        self.assertIn("QPERIAPT_ANDROID_SERIAL is required", producer)
        self.assertIn("QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical", producer)
        self.assertIn("refusing automatic Android device selection", producer)
        self.assertIn("android_command()", producer)
        self.assertIn("artifact/android_bounded_command.py invoke", producer)
        self.assertIn("artifact/android_bounded_command.py server-nodaemon", producer)
        self.assertNotIn('"$ADB" -L "$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer)
        self.assertNotIn("artifact/bounded_process.py run", producer)
        self.assertNotIn("artifact/bounded_process.py write", producer)
        bounded_process_source = (
            pathlib.Path(__file__).resolve().parent / "bounded_process.py"
        ).read_text(encoding="utf-8")
        self.assertIn("command timed out after", bounded_process_source)
        self.assertIn("command output exceeds", bounded_process_source)
        command_adapter_source = (
            pathlib.Path(__file__).resolve().parent / "android_bounded_command.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("argparse.REMAINDER", command_adapter_source)
        self.assertNotIn('"argv"', command_adapter_source)
        for operation in (
            "package-state",
            "observe-installed-apk",
            "install-apk",
            "uninstall-app",
            "read-result-text",
            "read-result-json",
            "capture-logcat",
        ):
            self.assertIn(f"android_command {operation}", producer)
        self.assertIn("request-owned-adb-stop --run-id", producer)
        self.assertIn("request-owned-emulator-stop --run-id", producer)
        self.assertIn("finalize-owned-adb-stop --run-id", producer)
        self.assertNotIn("android_command kill-server", producer)
        spawn_index = producer.index("ADB_PRIVATE_SERVER_PID=$!")
        handshake_index = producer.index("wait-owned-adb-server-start", spawn_index)
        restored_signal_trap_index = producer.index(
            "trap 'exit 129' HUP", handshake_index
        )
        preserve_index = producer.index(
            "ANDROID_RUNTIME_RECOVERY_PRESERVE=1", handshake_index
        )
        self.assertLess(spawn_index, handshake_index)
        self.assertLess(handshake_index, preserve_index)
        self.assertLess(preserve_index, restored_signal_trap_index)
        self.assertIn("ANDROID_RUNTIME_RECOVERY_PRESERVE=1", producer[handshake_index:])
        self.assertIn(
            'if [ "${ANDROID_RUNTIME_RECOVERY_PRESERVE:-0}" = "1" ]',
            producer,
        )
        emulator_request = producer.index("request-owned-emulator-stop --run-id")
        emulator_protocol_record = producer.index(
            "EMULATOR_PROTOCOL_STOP_REQUESTED=1", emulator_request
        )
        adb_request = producer.index("request-owned-adb-stop --run-id")
        adb_protocol_record = producer.index(
            "ADB_PROTOCOL_STOP_REQUESTED=1", adb_request
        )
        adb_wait = producer.index('wait "$ADB_PRIVATE_SERVER_PID"', adb_protocol_record)
        protocol_admission = producer.index(
            'if [ "${ADB_PROTOCOL_STOP_REQUESTED:-0}" != "1" ]'
        )
        proof_publication = producer.index("publish-staged-proof")
        self.assertLess(emulator_request, emulator_protocol_record)
        self.assertLess(adb_request, adb_protocol_record)
        self.assertLess(adb_protocol_record, adb_wait)
        self.assertLess(adb_wait, protocol_admission)
        self.assertLess(protocol_admission, proof_publication)
        self.assertNotIn("0 | 129 | 130 | 137 | 143", producer)
        cleanup_start = producer.index("cleanup_runtime()")
        cleanup_emulator_request = producer.index(
            "if ! request_owned_emulator_shutdown", cleanup_start
        )
        cleanup_emulator_wait = producer.index(
            "if stop_emulator_process", cleanup_emulator_request
        )
        self.assertLess(cleanup_emulator_request, cleanup_emulator_wait)
        self.assertIn("remaining_bounded_timeout()", producer)
        preinstall_observation = producer[
            producer.index("observe_preinstall_package_absence()") : preflight_index
        ]
        self.assertIn("preinstall_deadline=$(monotonic_deadline 45)", preinstall_observation)
        self.assertIn('"$preinstall_deadline" 5', preinstall_observation)
        self.assertIn("preinstall_consecutive_absent=0", preinstall_observation)
        self.assertIn(
            'if [ "$preinstall_consecutive_absent" -eq 3 ]; then',
            preinstall_observation,
        )
        self.assertIn("0:retryable:query-nonzero", preinstall_observation)
        self.assertIn("0:retryable:query-timeout", preinstall_observation)
        self.assertIn("state=retryable reason=%s consecutive=0", preinstall_observation)
        self.assertIn('2>>"$preinstall_observer_error"', preinstall_observation)
        self.assertIn("0:present)", preinstall_observation)
        self.assertIn("state=structural-error", preinstall_observation)
        self.assertIn("adb-package-query-preinstall-attempt-", preinstall_observation)
        self.assertIn("BOOT_COMPLETION_DEADLINE=$(monotonic_deadline 120)", producer)
        self.assertIn("RUNTIME_RESULT_DEADLINE=$(monotonic_deadline 90)", producer)
        self.assertIn(
            'android_command device-state \\\n\t\t\t--timeout-seconds "$emulator_attempt_timeout"',
            producer,
        )
        self.assertIn(
            'android_command boot-completed \\\n\t\t--timeout-seconds "$boot_attempt_timeout"',
            producer,
        )
        self.assertIn(
            'android_command read-result-text \\\n\t\t--timeout-seconds "$result_attempt_timeout"',
            producer,
        )
        self.assertNotIn('while [ "$i" -lt 90 ]; do', producer)
        self.assertNotIn('while [ "$i" -lt 120 ]; do', producer)
        self.assertIn("ADB_VENDOR_KEYS is not supported", producer)
        self.assertIn("ADB_SERVER_SOCKET is not supported", producer)
        self.assertIn("QPERIAPT_ADB is not supported", producer)
        self.assertNotIn("auto | macos-account | linux-account", producer)
        self.assertIn(
            "artifact/android_bounded_command.py adb-path", producer
        )
        self.assertIn("ANDROID_ADB_SERVER_ADDRESS is not supported", producer)
        self.assertIn("ANDROID_ADB_SERVER_PORT is not supported", producer)
        for variable in (
            "ADB_VENDOR_KEYS",
            "ADB_SERVER_SOCKET",
            "ANDROID_ADB_SERVER_ADDRESS",
            "ANDROID_ADB_SERVER_PORT",
            "ADB_MDNS",
            "ADB_MDNS_AUTO_CONNECT",
            "ADB_MDNS_OPENSCREEN",
            "ADB_USB",
            "ADB_EMU",
            "ADB_REJECT_KILL_SERVER",
            "ADB_LOCAL_TRANSPORT_MAX_PORT",
            "ADB_OSX_USB_CLEAR_ENDPOINTS",
            "ANDROID_ADB_LOG_PATH",
            "ADB_TRACE",
            "ADB_INSTALL_DEFAULT_INCREMENTAL",
            "ADB_LIBUSB",
            "ADB_LIBUSB_START_DETACHED",
        ):
            self.assertIn(f'"${{{variable}+x}}" = x', producer)
        self.assertIn("verify-adb-identity", producer)
        self.assertIn('--home-directory "$HOME"', producer)
        verifier_source = (
            pathlib.Path(__file__).resolve().parent / "android_device_proof.py"
        ).read_text(encoding="utf-8")
        emulator_control_source = (
            pathlib.Path(__file__).resolve().parent / "android_emulator_control.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "existing {label} is required before device proof", verifier_source
        )
        self.assertIn(
            "HOME must match the current account home directory", verifier_source
        )
        self.assertLess(
            producer.index("verify-adb-identity"),
            producer.index("server-nodaemon"),
        )
        device_selection_section = producer.index(
            "=== Select Android runtime device ==="
        )
        default_listener_gate = producer.index(
            "\nassert_default_adb_server_absent\n", device_selection_section
        )
        server_cleanup_arm = producer.index("ADB_PRIVATE_SERVER_CLEANUP_ARMED=1")
        capability_create = producer.index("create-capability", server_cleanup_arm)
        capability_arm = producer.index(
            "ANDROID_COMMAND_CAPABILITY_ARMED=1", server_cleanup_arm
        )
        server_start = producer.index("server-nodaemon", server_cleanup_arm)
        self.assertLess(capability_arm, capability_create)
        server_pid_capture = producer.index("ADB_PRIVATE_SERVER_PID=$!", server_start)
        client_transport_disable = producer.index(
            "export ADB_USB=0", server_pid_capture
        )
        recovery_identity_print = producer.index(
            "private-adb: pid=", server_pid_capture
        )
        initial_listener_check = producer.index("verify-adb-listener", server_start)
        first_server_check = producer.index(
            "verify-adb-server-status", initial_listener_check
        )
        first_listener_check = producer.index("verify-adb-listener", first_server_check)
        device_selection = producer.index("SERIAL=$(select_serial_or_empty)")
        second_server_check = producer.rindex("verify-adb-server-status")
        second_listener_check = producer.rindex("verify-adb-listener")
        proof_function = producer.index(
            'python3 - "$ROOT" "$RUN_ID"', device_selection
        )
        proof_staging_write = producer.index(
            "descriptor = os.open(proof, flags, 0o600)", proof_function
        )
        proof_publication = producer.index(
            "publish-staged-proof", second_listener_check
        )
        runtime_cleanup = producer.index(
            "cleanup_runtime_with_deferred_signals", second_listener_check
        )
        proof_emission = producer.index(
            "\nemit_android_runtime_proof\n", runtime_cleanup
        )
        final_default_listener_gate = producer.rindex(
            "\nassert_default_adb_server_absent\n"
        )
        proof_verification = producer.index(
            "artifact/android_device_proof.py verify \\", second_listener_check
        )
        proof_bundle = producer.index(
            "artifact/android_device_proof.py create-bundle", proof_verification
        )
        evidence_confirmation = producer.index(
            "ANDROID_PROOF_EVIDENCE_CONFIRMED=1", proof_bundle
        )
        pass_marker = producer.index(
            "ANDROID_DEVICE_RUNTIME_PASS", evidence_confirmation
        )
        self.assertLess(default_listener_gate, server_cleanup_arm)
        self.assertLess(server_cleanup_arm, server_start)
        self.assertLess(capability_arm, capability_create)
        self.assertLess(capability_create, server_start)
        self.assertLess(server_start, server_pid_capture)
        self.assertLess(server_pid_capture, client_transport_disable)
        self.assertLess(client_transport_disable, recovery_identity_print)
        self.assertLess(recovery_identity_print, initial_listener_check)
        self.assertLess(client_transport_disable, initial_listener_check)
        self.assertLess(initial_listener_check, first_server_check)
        self.assertLess(first_server_check, first_listener_check)
        self.assertLess(first_listener_check, device_selection)
        self.assertLess(proof_function, proof_staging_write)
        self.assertLess(second_server_check, second_listener_check)
        self.assertLess(second_listener_check, runtime_cleanup)
        self.assertLess(runtime_cleanup, final_default_listener_gate)
        self.assertLess(final_default_listener_gate, proof_emission)
        self.assertLess(proof_emission, proof_publication)
        self.assertLess(final_default_listener_gate, proof_publication)
        self.assertLess(second_listener_check, proof_publication)
        self.assertLess(proof_publication, proof_verification)
        self.assertLess(proof_verification, proof_bundle)
        self.assertLess(proof_bundle, evidence_confirmation)
        self.assertLess(evidence_confirmation, pass_marker)
        self.assertLess(second_listener_check, proof_verification)
        self.assertIn('--expected-identity "$ADB_LISTENER_IDENTITY"', producer)
        self.assertIn('--expected-pid "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertIn(
            '--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer
        )
        self.assertIn('--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY"', producer)
        self.assertIn("--expected-mdns 0", producer)
        self.assertIn('--expected-transport-kind "$EXPECTED_DEVICE_KIND"', producer)
        self.assertIn(
            'ADB_PRIVATE_SERVER_SOCKET_SPEC="localfilesystem:$ADB_PRIVATE_SERVER_SOCKET_PATH"',
            producer,
        )
        self.assertNotIn('"$ADB" -L "$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer)
        self.assertIn(
            'argv.extend(("--one-device", capability.expected_serial))',
            command_adapter_source,
        )
        self.assertIn(
            "endpoint did not refuse its loopback connection",
            emulator_control_source,
        )
        self.assertNotIn('"$ADB" start-server', producer)
        self.assertNotIn('"$ADB" kill-server', producer)
        self.assertNotIn('"$ADB" -s ', producer)
        self.assertNotIn('"$ADB" devices', producer)
        self.assertNotIn('"$ADB" server-status', producer)
        self.assertNotIn('[str(adb), "-s"', producer)
        self.assertNotIn('[str(adb), "version"', producer)
        self.assertNotIn('--one-device "$QPERIAPT_ANDROID_SERIAL"', producer)
        self.assertIn("export ADB_MDNS=0", producer)
        self.assertIn("export ADB_MDNS_AUTO_CONNECT=0", producer)
        self.assertIn("export ADB_LOCAL_TRANSPORT_MAX_PORT=5585", producer)
        self.assertIn("export ADB_USB=1", producer)
        self.assertIn("export ADB_EMU=0", producer)
        self.assertIn("physical Android evidence requires one USB transport", producer)
        self.assertEqual(producer.count("\nassert_default_adb_server_absent\n"), 3)
        self.assertIn(
            'PROOF_STAGING="$WORK/qperiapt-android-device-proof.json.pending"',
            producer,
        )
        self.assertIn("ANDROID_PROOF_EVIDENCE_CONFIRMED=1", producer)
        self.assertIn("cleanup_unconfirmed_proof", producer)
        self.assertIn('proof_destination.parent / "apksigner-verify.txt"', producer)
        self.assertIn('proof_destination.parent / "zipalign-verify.txt"', producer)
        self.assertIn("was not already authorized", producer)
        self.assertIn("ANDROID_APP_INSTALL_CONFIRMED=1", producer)
        self.assertIn("required_absent_observations=8", producer)
        self.assertIn("Android app cleanup outcome is unresolved", producer)
        self.assertIn(
            "refusing to boot a proof AVD while another adb device is already online",
            producer,
        )
        self.assertIn(
            "ANDROID_EMULATOR_PORT=${QPERIAPT_ANDROID_EMULATOR_PORT:-5584}",
            producer,
        )
        self.assertIn("ANDROID_BOOT_AVD=${QPERIAPT_ANDROID_BOOT_AVD:-0}", producer)
        self.assertIn(
            "ANDROID_KEEP_EMULATOR=${QPERIAPT_ANDROID_KEEP_EMULATOR:-0}", producer
        )
        self.assertIn(
            "EXPECTED_DEVICE_KIND=${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-any}", producer
        )
        self.assertIn(
            "Android release emulator proof requires QPERIAPT_ANDROID_BOOT_AVD=1",
            producer,
        )
        self.assertIn(
            "Android release emulator proof must use the script-started cold-boot AVD",
            producer,
        )
        self.assertIn(
            "Android release mode requires an explicit QPERIAPT_ANDROID_EXPECT_DEVICE_KIND",
            producer,
        )
        self.assertIn(
            'EXPECTED_COMMAND_SERIAL="emulator-$ANDROID_EMULATOR_PORT"', producer
        )
        self.assertIn("EXPECTED_EMULATOR_SERIAL=$EXPECTED_COMMAND_SERIAL", producer)
        self.assertIn(
            '"-port",\n        str(receipt.console_port),', command_adapter_source
        )
        self.assertIn('"-no-direct-adb",', command_adapter_source)
        self.assertIn("SERIAL=$EXPECTED_EMULATOR_SERIAL", producer)
        self.assertIn(
            "temporary Android emulator exited before its bound adb serial", producer
        )
        self.assertIn('"-read-only",', command_adapter_source)
        self.assertNotIn(
            'if [ -z "$SERIAL" ] && [ "${QPERIAPT_ANDROID_BOOT_AVD:-0}" = "1" ]',
            producer,
        )

    def test_owned_avd_registration_is_identity_bound_and_precedes_selection(
        self,
    ) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        private_server = producer.index(
            "artifact/android_bounded_command.py server-nodaemon"
        )
        emulator_start = producer.index("emulator-nodaemon", private_server)
        listener_wait = producer.index(
            "wait_for_owned_emulator_listeners 90", emulator_start
        )
        registration = producer.index(
            "wait_for_owned_emulator_registration 30", listener_wait
        )
        registered_status = producer.index("server-status-registered", registration)
        registered_listener = producer.index("lsof-registered", registered_status)
        device_state = producer.index(
            "android_command device-state", registered_listener
        )
        self.assertLess(private_server, emulator_start)
        self.assertLess(emulator_start, listener_wait)
        self.assertLess(listener_wait, registration)
        self.assertLess(registration, registered_status)
        self.assertLess(registered_status, registered_listener)
        self.assertLess(registered_listener, device_state)
        self.assertIn("verify-owned-emulator-listeners", producer)
        self.assertIn("wait-owned-emulator-backend", producer)
        self.assertIn(
            'EMULATOR_RECEIPT_PID=${EMULATOR_PROCESS_IDENTITY%%:*}', producer
        )
        self.assertIn(
            '[ "$EMULATOR_RECEIPT_PID" != "$EMULATOR_PID" ]', producer
        )
        self.assertNotIn("wait-owned-process-exec", producer)
        self.assertNotIn("verify-owned-process", producer)
        self.assertIn("EMULATOR_ADB_PORT=$((ANDROID_EMULATOR_PORT + 1))", producer)
        self.assertIn(
            f'"schema": {android_device_proof.PROOF_SCHEMA_VERSION}', producer
        )
        self.assertIn('"emulator_control": emulator_control', producer)
        self.assertIn('"$EMULATOR_PROCESS_IDENTITY" "$ADB_LISTENER_IDENTITY"', producer)
        self.assertIn('"$DIST/emulator-listeners.txt"', producer)
        self.assertIn('"$DIST/adb-emulator-registration.txt"', producer)
        self.assertIn('"${ADB_SERVER_STATUS_REGISTERED:-}"', producer)
        self.assertIn('"${ADB_LISTENER_REGISTERED:-}"', producer)
        self.assertIn(
            "from artifact.android_device_proof import build_emulator_control_receipt",
            producer,
        )
        self.assertIn("emulator_control = build_emulator_control_receipt(", producer)
        self.assertIn("process_identity=emulator_process_identity", producer)
        self.assertIn("private_adb_identity=private_adb_identity", producer)
        self.assertIn("emulator_control = None", producer)
        self.assertNotIn('"process_identity": emulator_process_identity', producer)
        self.assertNotIn('"identity": private_adb_identity', producer)
        self.assertIn("request_owned_emulator_shutdown()", producer)
        cleanup_start = producer.index("cleanup_runtime()")
        cleanup_end = producer.index(
            "cleanup_runtime_with_deferred_signals()", cleanup_start
        )
        cleanup = producer[cleanup_start:cleanup_end]
        self.assertIn("request_owned_emulator_shutdown", cleanup)
        self.assertNotIn(
            '[ -n "${SERIAL:-}" ] && ! android_command emulator-kill', cleanup
        )
        self.assertNotIn('kill -TERM "$EMULATOR_PID"', producer)
        self.assertNotIn('kill -KILL "$EMULATOR_PID"', producer)

    def test_preinstall_observation_recovers_without_success_stderr(self) -> None:
        result, files, query_count, install_called = self._run_preinstall_observation(
            ("nonzero", "absent", "absent", "absent")
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, b"")
        self.assertEqual(query_count, 4)
        self.assertTrue(install_called)
        self.assertEqual(
            files["adb-package-state-observation.log"].decode("ascii").splitlines(),
            [
                "phase=preinstall invocation=1 attempt=1 state=retryable reason=query-nonzero consecutive=0",
                "phase=preinstall invocation=1 attempt=2 state=absent consecutive=1",
                "phase=preinstall invocation=1 attempt=3 state=absent consecutive=2",
                "phase=preinstall invocation=1 attempt=4 state=absent consecutive=3",
            ],
        )
        self.assertEqual(files["adb-package-query-preinstall-attempt-1.err"], b"")
        self.assertEqual(
            files["adb-package-query-preinstall-attempt-1.observer.err"], b""
        )

    def test_preinstall_observation_resets_interleaved_absence(self) -> None:
        result, files, query_count, install_called = self._run_preinstall_observation(
            ("absent", "timeout", "absent", "absent", "absent")
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(result.stderr, b"")
        self.assertEqual(query_count, 5)
        self.assertTrue(install_called)
        log = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("phase=preinstall invocation=1 attempt=1 state=absent consecutive=1\n", log)
        self.assertIn("phase=preinstall invocation=1 attempt=2 state=retryable reason=query-timeout consecutive=0\n", log)
        self.assertIn("phase=preinstall invocation=1 attempt=3 state=absent consecutive=1\n", log)
        self.assertTrue(log.endswith("phase=preinstall invocation=1 attempt=5 state=absent consecutive=3\n"))

    def test_preinstall_observation_rejects_present_immediately(self) -> None:
        result, files, query_count, install_called = self._run_preinstall_observation(
            ("present",)
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(query_count, 1)
        self.assertFalse(install_called)
        self.assertIn(b"refusing to replace a pre-existing Android package", result.stderr)
        self.assertEqual(
            files["adb-package-state-observation.log"],
            b"phase=preinstall invocation=1 attempt=1 state=present consecutive=0\n",
        )

    def test_preinstall_observation_deadline_fails_without_install(self) -> None:
        result, files, query_count, install_called = self._run_preinstall_observation(
            ("nonzero", "timeout"),
            bounded_remaining_calls=4,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(query_count, 2)
        self.assertFalse(install_called)
        self.assertIn(
            b"package absence did not stabilize within 45 seconds",
            result.stderr,
        )
        self.assertEqual(
            files["adb-package-state-observation.log"].decode("ascii").splitlines(),
            [
                "phase=preinstall invocation=1 attempt=1 state=retryable reason=query-nonzero consecutive=0",
                "phase=preinstall invocation=1 attempt=2 state=retryable reason=query-timeout consecutive=0",
            ],
        )

    def test_preinstall_propagates_structural_adapter_results_without_install(
        self,
    ) -> None:
        for outcome in ("structural", "malformed"):
            with self.subTest(outcome=outcome):
                result, files, query_count, install_called = (
                    self._run_preinstall_observation((outcome,))
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(query_count, 1)
                self.assertFalse(install_called)
                self.assertEqual(
                    files["adb-package-state-observation.log"],
                    b"phase=preinstall invocation=1 attempt=1 state=structural-error exit=2 consecutive=0\n",
                )

    def test_installed_package_ownership_requires_two_consecutive_exact_observations(
        self,
    ) -> None:
        path_a = "a" * 64
        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (
                    f"exact:{path_a}",
                    "retryable:bytes-mismatch",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                )
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(result.stderr, b"")
        self.assertEqual(observation_count, 4)
        self.assertEqual(signer_count, 1)
        self.assertEqual(
            files["adb-package-state-observation.log"]
            .decode("ascii")
            .splitlines(),
            [
                f"phase=postinstall invocation=1 attempt=1 state=exact path_sha256={path_a} consecutive=1",
                "phase=postinstall invocation=1 attempt=2 state=retryable reason=bytes-mismatch consecutive=0",
                f"phase=postinstall invocation=1 attempt=3 state=exact path_sha256={path_a} consecutive=1",
                f"phase=postinstall invocation=1 attempt=4 state=exact path_sha256={path_a} consecutive=2",
            ],
        )

    def test_installed_package_ownership_resets_when_canonical_path_changes(
        self,
    ) -> None:
        path_a = "a" * 64
        path_b = "b" * 64
        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (f"exact:{path_a}", f"exact:{path_b}", f"exact:{path_b}")
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(observation_count, 3)
        self.assertEqual(signer_count, 1)
        log = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn(f"path_sha256={path_b} consecutive=1\n", log)
        self.assertTrue(log.endswith(f"path_sha256={path_b} consecutive=2\n"))

    def test_ownership_observation_appends_to_the_existing_sanitized_journal(
        self,
    ) -> None:
        path_a = "a" * 64
        prefix = (
            "phase=preinstall invocation=1 attempt=1 "
            "state=absent consecutive=1\n"
        )
        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (f"exact:{path_a}", f"exact:{path_a}"),
                journal_prefix=prefix,
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(observation_count, 2)
        self.assertEqual(signer_count, 1)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertTrue(journal.startswith(prefix))
        self.assertEqual(journal.count("phase=postinstall invocation=1"), 2)

    def test_installed_package_ownership_deadline_never_accepts_one_exact_sample(
        self,
    ) -> None:
        result, _files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation((f"exact:{'a' * 64}",))
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(observation_count, 1)
        self.assertEqual(signer_count, 0)
        self.assertIn(b"did not converge within its total deadline", result.stderr)

    def test_installed_package_ownership_propagates_structural_and_signer_failures(
        self,
    ) -> None:
        result, _files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(("structural",))
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(observation_count, 1)
        self.assertEqual(signer_count, 0)
        self.assertIn(b"failed structurally", result.stderr)

        path_a = "a" * 64
        result, _files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (f"exact:{path_a}", f"exact:{path_a}"),
                signer_status=2,
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(observation_count, 2)
        self.assertEqual(signer_count, 1)

    def test_installed_package_ownership_rejects_unknown_retry_reason(self) -> None:
        result, _files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                ("retryable:unexpected",)
            )
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(observation_count, 1)
        self.assertEqual(signer_count, 0)
        self.assertIn(b"malformed retry reason", result.stderr)

    def test_postinstall_recovers_owned_emulator_transport_then_reconverges(
        self,
    ) -> None:
        path_a = "a" * 64
        for recovery_outcome in ("recovered", "race-device"):
            with self.subTest(recovery_outcome=recovery_outcome):
                result, files, observation_count, signer_count = (
                    self._run_installed_package_ownership_observation(
                        (
                            f"exact:{path_a}",
                            "retryable:package-unavailable",
                            f"exact:{path_a}",
                            f"exact:{path_a}",
                        ),
                        transport_recovery_outcomes=(recovery_outcome,),
                        boot_owned_emulator=True,
                    )
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
                self.assertEqual(observation_count, 4)
                self.assertEqual(signer_count, 1)
                self.assertEqual(files["fixture-recovery-count.txt"], b"1\n")
                self.assertEqual(files["fixture-recovery-attempted.txt"], b"1\n")
                journal = files["adb-package-state-observation.log"].decode("ascii")
                self.assertIn(
                    "phase=postinstall invocation=1 attempt=2 "
                    f"transport-recovery={recovery_outcome}\n",
                    journal,
                )
                recovery = journal.index("transport-recovery=")
                first_fresh_exact = journal.index(
                    f"attempt=3 state=exact path_sha256={path_a} consecutive=1"
                )
                second_fresh_exact = journal.index(
                    f"attempt=4 state=exact path_sha256={path_a} consecutive=2"
                )
                self.assertLess(recovery, first_fresh_exact)
                self.assertLess(first_fresh_exact, second_fresh_exact)

    def test_postinstall_transport_recovery_requires_prior_exact_owned_emulator(
        self,
    ) -> None:
        path_a = "a" * 64
        for (
            outcomes,
            boot_owned_emulator,
            device_kind_override,
            emulator_started_override,
        ) in (
            (
                (
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                True,
                None,
                None,
            ),
            (
                (
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                False,
                None,
                None,
            ),
            (
                (
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                False,
                "emulator",
                True,
            ),
            (
                (
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                True,
                None,
                False,
            ),
        ):
            with self.subTest(
                prior_exact=outcomes[0].startswith("exact:"),
                boot_owned_emulator=boot_owned_emulator,
                device_kind_override=device_kind_override,
                emulator_started_override=emulator_started_override,
            ):
                result, files, _observation_count, signer_count = (
                    self._run_installed_package_ownership_observation(
                        outcomes,
                        transport_recovery_outcomes=("recovered",),
                        boot_owned_emulator=boot_owned_emulator,
                        device_kind_override=device_kind_override,
                        emulator_started_override=emulator_started_override,
                    )
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
                self.assertEqual(signer_count, 1)
                self.assertEqual(files["fixture-recovery-count.txt"], b"0\n")
                self.assertEqual(files["fixture-recovery-attempted.txt"], b"0\n")
                self.assertNotIn(
                    "transport-recovery=",
                    files["adb-package-state-observation.log"].decode("ascii"),
                )

    def test_postinstall_transport_recovery_never_masks_integrity_retries(
        self,
    ) -> None:
        path_a = "a" * 64
        for retry_reason in (
            "pull-failed",
            "path-changed",
            "bytes-mismatch",
            "deadline-exhausted",
        ):
            with self.subTest(retry_reason=retry_reason):
                result, files, _observation_count, signer_count = (
                    self._run_installed_package_ownership_observation(
                        (
                            f"exact:{path_a}",
                            f"retryable:{retry_reason}",
                            f"exact:{path_a}",
                            f"exact:{path_a}",
                        ),
                        transport_recovery_outcomes=("recovered",),
                        boot_owned_emulator=True,
                    )
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
                self.assertEqual(signer_count, 1)
                self.assertEqual(files["fixture-recovery-count.txt"], b"0\n")
                self.assertEqual(files["fixture-recovery-attempted.txt"], b"0\n")

    def test_postinstall_transport_recovery_is_one_shot_and_not_proof(self) -> None:
        path_a = "a" * 64
        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                transport_recovery_outcomes=("retryable:registration-failed",),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(observation_count, 6)
        self.assertEqual(signer_count, 1)
        self.assertEqual(files["fixture-recovery-count.txt"], b"1\n")
        self.assertEqual(files["fixture-recovery-attempted.txt"], b"1\n")
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertEqual(journal.count("transport-recovery="), 1)
        self.assertIn("transport-recovery=retryable reason=registration-failed", journal)

        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                ),
                transport_recovery_outcomes=("recovered",),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(observation_count, 3)
        self.assertEqual(signer_count, 0)
        self.assertEqual(files["fixture-recovery-count.txt"], b"1\n")
        self.assertIn(b"did not converge within its total deadline", result.stderr)

    def test_postinstall_recovery_requires_remaining_budget_and_propagates_failures(
        self,
    ) -> None:
        path_a = "a" * 64
        result, files, observation_count, signer_count = (
            self._run_installed_package_ownership_observation(
                (f"exact:{path_a}", "retryable:package-unavailable"),
                transport_recovery_outcomes=("recovered",),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(observation_count, 2)
        self.assertEqual(signer_count, 0)
        self.assertEqual(files["fixture-recovery-count.txt"], b"0\n")
        self.assertEqual(files["fixture-recovery-attempted.txt"], b"0\n")

        for recovery_outcome in (
            "retryable:transport-inconclusive",
            "retryable:registration-failed",
            "retryable:post-state-unavailable",
        ):
            with self.subTest(recovery_outcome=recovery_outcome):
                result, files, observation_count, signer_count = (
                    self._run_installed_package_ownership_observation(
                        (
                            f"exact:{path_a}",
                            "retryable:package-unavailable",
                            f"exact:{path_a}",
                        ),
                        transport_recovery_outcomes=(recovery_outcome,),
                        boot_owned_emulator=True,
                    )
                )
                self.assertEqual(result.returncode, 1)
                self.assertEqual(observation_count, 3)
                self.assertEqual(signer_count, 0)
                self.assertEqual(files["fixture-recovery-count.txt"], b"1\n")
                self.assertEqual(files["fixture-recovery-attempted.txt"], b"1\n")

        for recovery_outcome, expected_status in (
            ("structural", 2),
            ("malformed", 2),
            ("multiline", 2),
            ("diagnostic", 2),
            ("signal129", 129),
            ("signal130", 130),
            ("signal143", 143),
        ):
            with self.subTest(recovery_outcome=recovery_outcome):
                result, files, observation_count, signer_count = (
                    self._run_installed_package_ownership_observation(
                        (
                            f"exact:{path_a}",
                            "retryable:package-unavailable",
                            f"exact:{path_a}",
                        ),
                        transport_recovery_outcomes=(recovery_outcome,),
                        boot_owned_emulator=True,
                    )
                )
                self.assertEqual(result.returncode, expected_status)
                self.assertEqual(observation_count, 2)
                self.assertEqual(signer_count, 0)
                self.assertEqual(files["fixture-recovery-count.txt"], b"1\n")
                self.assertEqual(files["fixture-recovery-attempted.txt"], b"1\n")

    def test_cleanup_reverifies_ownership_before_one_uninstall_and_three_absences(
        self,
    ) -> None:
        result, files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present", "present", "absent", "absent", "absent"),
            ownership_outcomes=(f"exact:{'a' * 64}", f"exact:{'a' * 64}"),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(calls.count("package-state"), 5)
        self.assertEqual(calls.count("observe-installed-apk"), 2)
        self.assertEqual(signer_count, 1)
        self.assertFalse(copy_exists)
        self.assertEqual(
            files["adb-package-state-observation.log"].decode("ascii").splitlines(),
            [
                "phase=cleanup invocation=1 attempt=1 state=present consecutive=0",
                f"phase=cleanup invocation=1 attempt=1 state=exact path_sha256={'a' * 64} consecutive=1",
                "phase=cleanup invocation=1 attempt=2 state=present consecutive=0",
                f"phase=cleanup invocation=1 attempt=2 state=exact path_sha256={'a' * 64} consecutive=2",
                "phase=cleanup invocation=1 attempt=2 uninstall=request-returned-zero",
                "phase=cleanup invocation=1 attempt=3 state=absent consecutive=1",
                "phase=cleanup invocation=1 attempt=4 state=absent consecutive=2",
                "phase=cleanup invocation=1 attempt=5 state=absent consecutive=3",
            ],
        )
        self.assertIn("adb-package-query-cleanup-1-attempt-1.txt", files)
        self.assertIn("adb-package-query-cleanup-1-attempt-5.txt", files)

    def test_cleanup_never_uninstalls_without_converged_ownership(self) -> None:
        result, _files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present", "nonzero"),
            ownership_outcomes=("retryable:package-unavailable",),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            calls, ["package-state", "observe-installed-apk", "package-state"]
        )
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

        result, _files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present",),
            ownership_outcomes=("structural",),
            remaining_calls_per_invocation=(2,),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, ["package-state", "observe-installed-apk"])
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

    def test_cleanup_requeries_package_state_between_ownership_samples(self) -> None:
        path_a = "a" * 64
        result, files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present", "present", "present", "absent", "absent", "absent"),
            ownership_outcomes=(
                "retryable:package-unavailable",
                "retryable:package-unavailable",
                f"exact:{path_a}",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(
            calls,
            [
                "package-state",
                "observe-installed-apk",
                "package-state",
                "observe-installed-apk",
                "package-state",
                "observe-installed-apk",
                "package-state",
                "package-state",
                "package-state",
            ],
        )
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("attempt=1 state=retryable reason=package-unavailable", journal)
        self.assertIn("attempt=2 state=retryable reason=package-unavailable", journal)
        self.assertIn(
            f"attempt=3 state=exact path_sha256={path_a} consecutive=1", journal
        )
        self.assertTrue(journal.endswith("attempt=6 state=absent consecutive=3\n"))

    def test_cleanup_ownership_streak_resets_on_retry_and_path_change(self) -> None:
        path_a = "a" * 64
        path_b = "b" * 64
        result, files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present",) * 5 + ("absent",) * 3,
            ownership_outcomes=(
                f"exact:{path_a}",
                "retryable:path-changed",
                f"exact:{path_a}",
                f"exact:{path_b}",
                f"exact:{path_b}",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("observe-installed-apk"), 5)
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(signer_count, 1)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn(f"attempt=1 state=exact path_sha256={path_a} consecutive=1", journal)
        self.assertIn("attempt=2 state=retryable reason=path-changed consecutive=0", journal)
        self.assertIn(f"attempt=3 state=exact path_sha256={path_a} consecutive=1", journal)
        self.assertIn(f"attempt=4 state=exact path_sha256={path_b} consecutive=1", journal)
        self.assertIn(f"attempt=5 state=exact path_sha256={path_b} consecutive=2", journal)
        self.assertFalse(copy_exists)

    def test_cleanup_ci_interleaving_recovers_before_single_uninstall(self) -> None:
        path_a = "a" * 64
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("present",) * 6 + ("absent",) * 3,
                ownership_outcomes=(
                    "retryable:package-unavailable",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    "retryable:package-unavailable",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("package-state"), 9)
        self.assertEqual(calls.count("observe-installed-apk"), 6)
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(signer_count, 1)
        self.assertFalse(copy_exists)

    def test_cleanup_package_query_retry_resets_one_exact_sample(self) -> None:
        path_a = "a" * 64
        result, files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("present", "nonzero", "present", "present") + ("absent",) * 3,
                ownership_outcomes=(
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(signer_count, 1)
        self.assertFalse(copy_exists)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("attempt=2 state=retryable reason=query-nonzero", journal)
        self.assertEqual(journal.count("state=exact path_sha256="), 3)
        self.assertEqual(journal.count("state=exact path_sha256=" + path_a + " consecutive=1"), 2)

    def test_cleanup_recovers_owned_emulator_transport_then_reconverges(self) -> None:
        path_a = "a" * 64
        result, files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("device-unavailable", "present", "present") + ("absent",) * 3,
                ownership_outcomes=(f"exact:{path_a}", f"exact:{path_a}"),
                transport_recovery_outcomes=("recovered",),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("recover-emulator-transport"), 1)
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(signer_count, 1)
        self.assertFalse(copy_exists)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("transport-recovery=recovered", journal)
        recovery = journal.index("transport-recovery=recovered")
        first_exact = journal.index("state=exact path_sha256=", recovery)
        self.assertLess(recovery, first_exact)

    def test_cleanup_transport_recovery_resets_prior_ownership_streak(self) -> None:
        path_a = "a" * 64
        result, files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("present", "device-unavailable", "present", "present")
                + ("absent",) * 3,
                ownership_outcomes=(
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                    f"exact:{path_a}",
                ),
                transport_recovery_outcomes=("race-device",),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("recover-emulator-transport"), 1)
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(signer_count, 1)
        self.assertFalse(copy_exists)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("transport-recovery=race-device", journal)
        self.assertEqual(
            journal.count(
                f"state=exact path_sha256={path_a} consecutive=1"
            ),
            2,
        )

    def test_cleanup_transport_recovery_is_once_per_run_and_emulator_only(self) -> None:
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("device-unavailable", "device-unavailable"),
                transport_recovery_outcomes=("retryable:registration-failed",),
                cleanup_invocations=2,
                remaining_calls_per_invocation=(2, 2),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls.count("recover-emulator-transport"), 1)
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

        result, _files, calls, _signer_count, _copy_exists = (
            self._run_cleanup_observation(("device-unavailable",))
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("recover-emulator-transport", calls)
        self.assertNotIn("uninstall-app", calls)

    def test_cleanup_does_not_repeat_a_postinstall_transport_recovery(self) -> None:
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("device-unavailable",),
                transport_recovery_outcomes=("recovered",),
                boot_owned_emulator=True,
                transport_recovery_attempted=True,
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("recover-emulator-transport", calls)
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

    def test_cleanup_recovery_flag_is_set_only_after_remaining_budget(self) -> None:
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("device-unavailable", "device-unavailable"),
                transport_recovery_outcomes=("retryable:registration-failed",),
                cleanup_invocations=2,
                remaining_calls_per_invocation=(1, 2),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls.count("recover-emulator-transport"), 1)
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

    def test_cleanup_transport_recovery_preserves_signal_status(self) -> None:
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("device-unavailable",),
                transport_recovery_outcomes=("signal129",),
                remaining_calls_per_invocation=(2,),
                boot_owned_emulator=True,
            )
        )
        self.assertEqual(result.returncode, 129)
        self.assertEqual(calls.count("recover-emulator-transport"), 1)
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)

    def test_runtime_cleanup_preserves_app_signal_and_failed_retirement_status(
        self,
    ) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        cleanup_start = producer.index("cleanup_runtime() {")
        cleanup_end = producer.index(
            "\n}\n\ncleanup_runtime_with_deferred_signals()", cleanup_start
        )
        cleanup_function = producer[cleanup_start : cleanup_end + len("\n}\n")]
        normal_call = producer[producer.index("if cleanup_android_app; then", cleanup_end) :]
        self.assertIn("app_cleanup_status=$?", normal_call)
        self.assertIn('exit "$app_cleanup_status"', normal_call)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            retirement = root / "retirement.txt"
            script = f"""
set -eu
RETIREMENT={shlex.quote(str(retirement))}
RUN_ID={'a' * 32}
ANDROID_RUNTIME_RECOVERY_PRESERVE=0
KEYSTORE=
ANDROID_APP_CLEANUP_ARMED=1
ADB=owned
SERIAL=emulator-5584
EMULATOR_STARTED=0
ADB_PRIVATE_SERVER_CLEANUP_ARMED=0
ANDROID_COMMAND_CAPABILITY_ARMED=0
ANDROID_RUNTIME_RECOVERY_ARMED=1
ADB_PROTOCOL_STOP_REQUESTED=1
EMULATOR_PROTOCOL_STOP_REQUESTED=1
ANDROID_BOOT_AVD=0
ANDROID_RUNTIME_CLEANUP_COMPLETED=0
cleanup_android_app() {{ return 129; }}
python3() {{ printf '%s\n' "$*" >"$RETIREMENT"; return 0; }}
{cleanup_function}
if cleanup_runtime 0; then
    exit 0
else
    cleanup_status=$?
fi
test "$cleanup_status" -eq 129
test "$ANDROID_RUNTIME_CLEANUP_COMPLETED" -eq 0
exit "$cleanup_status"
"""
            result = subprocess.run(
                ["/bin/sh", "-c", script],
                cwd=pathlib.Path(__file__).resolve().parent.parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 129, result.stderr.decode("utf-8"))
            retirement_args = retirement.read_text(encoding="ascii")
            self.assertIn("retire-failed-runtime", retirement_args)
            self.assertIn("--primary-exit-status 129", retirement_args)

    def test_cleanup_transport_recovery_rejects_structural_or_malformed_results(
        self,
    ) -> None:
        for outcome in ("structural", "malformed", "diagnostic"):
            with self.subTest(outcome=outcome):
                result, _files, calls, signer_count, copy_exists = (
                    self._run_cleanup_observation(
                        ("device-unavailable",),
                        transport_recovery_outcomes=(outcome,),
                        boot_owned_emulator=True,
                        remaining_calls_per_invocation=(3,),
                    )
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(calls.count("recover-emulator-transport"), 1)
                self.assertNotIn("uninstall-app", calls)
                self.assertEqual(signer_count, 0)
                self.assertFalse(copy_exists)

    def test_cleanup_deadline_after_one_exact_removes_copy_without_uninstall(self) -> None:
        path_a = "a" * 64
        result, _files, calls, signer_count, copy_exists = (
            self._run_cleanup_observation(
                ("present",),
                ownership_outcomes=(f"exact:{path_a}",),
                remaining_calls_per_invocation=(3,),
            )
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ["package-state", "observe-installed-apk"])
        self.assertEqual(signer_count, 0)
        self.assertNotIn("uninstall-app", calls)
        self.assertFalse(copy_exists)

    def test_cleanup_ownership_structural_failure_is_immediate(self) -> None:
        result, files, calls, signer_count, copy_exists = self._run_cleanup_observation(
            ("present", "absent"),
            ownership_outcomes=("structural",),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(calls, ["package-state", "observe-installed-apk"])
        self.assertNotIn("uninstall-app", calls)
        self.assertEqual(signer_count, 0)
        self.assertFalse(copy_exists)
        self.assertIn(
            "state=structural-error exit=2",
            files["adb-package-state-observation.log"].decode("ascii"),
        )

    def test_cleanup_propagates_structural_package_state_without_uninstall(self) -> None:
        for outcome in ("structural", "malformed"):
            with self.subTest(outcome=outcome):
                result, files, calls, _signer_count, _copy_exists = (
                    self._run_cleanup_observation((outcome,))
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(calls, ["package-state"])
                self.assertNotIn("uninstall-app", calls)
                self.assertEqual(
                    files["adb-package-state-observation.log"],
                    b"phase=cleanup invocation=1 attempt=1 state=structural-error exit=2 consecutive=0\n",
                )

    def test_cleanup_reconciles_unknown_uninstall_only_after_owned_observation(
        self,
    ) -> None:
        result, files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("present", "present", "absent", "absent", "absent"),
            ownership_outcomes=(f"exact:{'a' * 64}", f"exact:{'a' * 64}"),
            uninstall_status=17,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertIn(
            "phase=cleanup invocation=1 attempt=2 uninstall=unknown-or-failed",
            files["adb-package-state-observation.log"].decode("ascii"),
        )

    def test_cleanup_retries_post_uninstall_query_then_requires_three_absences(
        self,
    ) -> None:
        result, files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("present", "present", "nonzero", "absent", "absent", "absent"),
            ownership_outcomes=(f"exact:{'a' * 64}", f"exact:{'a' * 64}"),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(calls.count("package-state"), 6)
        self.assertEqual(
            files["adb-package-state-observation.log"].decode("ascii").splitlines(),
            [
                "phase=cleanup invocation=1 attempt=1 state=present consecutive=0",
                f"phase=cleanup invocation=1 attempt=1 state=exact path_sha256={'a' * 64} consecutive=1",
                "phase=cleanup invocation=1 attempt=2 state=present consecutive=0",
                f"phase=cleanup invocation=1 attempt=2 state=exact path_sha256={'a' * 64} consecutive=2",
                "phase=cleanup invocation=1 attempt=2 uninstall=request-returned-zero",
                "phase=cleanup invocation=1 attempt=3 state=retryable reason=query-nonzero consecutive=0",
                "phase=cleanup invocation=1 attempt=4 state=absent consecutive=1",
                "phase=cleanup invocation=1 attempt=5 state=absent consecutive=2",
                "phase=cleanup invocation=1 attempt=6 state=absent consecutive=3",
            ],
        )

    def test_two_cleanup_invocations_share_the_single_uninstall_state(self) -> None:
        result, files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("present", "present", "present", "absent", "absent", "absent"),
            ownership_outcomes=(f"exact:{'a' * 64}", f"exact:{'a' * 64}"),
            cleanup_invocations=2,
            remaining_calls_per_invocation=(7, 7),
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(calls.count("package-state"), 6)
        journal = files["adb-package-state-observation.log"].decode("ascii")
        self.assertIn("phase=cleanup invocation=1 attempt=1 state=present", journal)
        self.assertIn(
            "phase=cleanup invocation=2 attempt=1 state=present", journal
        )
        self.assertIn(
            "phase=cleanup invocation=2 attempt=1 uninstall=still-present-after-request",
            journal,
        )
        self.assertTrue(
            journal.endswith(
                "phase=cleanup invocation=2 attempt=4 state=absent consecutive=3\n"
            )
        )

    def test_cleanup_never_repeats_an_uninstall_request_that_remains_present(
        self,
    ) -> None:
        result, files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("present", "present", "present", "present"),
            ownership_outcomes=(f"exact:{'a' * 64}", f"exact:{'a' * 64}"),
            uninstall_status=17,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls.count("uninstall-app"), 1)
        self.assertEqual(calls.count("package-state"), 4)
        log = files["adb-package-state-observation.log"].decode("ascii")
        self.assertEqual(log.count("uninstall=still-present-after-request"), 2)

    def test_cleanup_preserves_numbered_raw_diagnostics_until_retry_deadline(self) -> None:
        result, files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("nonzero", "timeout")
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ["package-state", "package-state"])
        self.assertIn("adb-package-query-cleanup-1-attempt-1.err", files)
        self.assertIn("adb-package-query-cleanup-1-attempt-2.err", files)
        self.assertEqual(files["adb-package-query-cleanup-1-attempt-1.err"], b"")
        self.assertEqual(files["adb-package-query-cleanup-1-attempt-2.err"], b"")
        self.assertEqual(
            files["adb-package-state-observation.log"].decode("ascii").splitlines(),
            [
                "phase=cleanup invocation=1 attempt=1 state=retryable reason=query-nonzero consecutive=0",
                "phase=cleanup invocation=1 attempt=2 state=retryable reason=query-timeout consecutive=0",
            ],
        )
        self.assertIn(b"cleanup outcome is unresolved", result.stderr)

    def test_unconfirmed_install_cleanup_requires_eight_absent_observations(
        self,
    ) -> None:
        result, _files, calls, _signer_count, _copy_exists = self._run_cleanup_observation(
            ("absent",) * 8,
            install_confirmed=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls, ["package-state"] * 8)
        self.assertNotIn("uninstall-app", calls)

    def test_install_runs_once_and_confirms_only_after_ownership_converges(self) -> None:
        result, calls, confirmed = self._run_install_confirmation(0)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        self.assertEqual(calls, ["install-apk", "observe-owned-installed-package"])
        self.assertTrue(confirmed)

        for ownership_status in (1, 2):
            with self.subTest(ownership_status=ownership_status):
                result, calls, confirmed = self._run_install_confirmation(
                    ownership_status
                )
                self.assertEqual(result.returncode, ownership_status)
                self.assertEqual(
                    calls,
                    ["install-apk", "observe-owned-installed-package"],
                )
                self.assertFalse(confirmed)
                self.assertIn(b"ownership did not converge", result.stderr)

        result, calls, confirmed = self._run_install_confirmation(
            0, install_status=17
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(calls, ["install-apk"])
        self.assertFalse(confirmed)
        self.assertIn(b"APK installation failed", result.stderr)

    def test_owned_avd_home_is_code_derived_and_verified_before_runtime_mutation(
        self,
    ) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        ambient_rejection = producer.index(
            'if [ "${ANDROID_AVD_HOME+x}" = x ]; then'
        )
        fixed_selection = producer.index(
            "artifact/android_bounded_command.py avd-home-path",
            ambient_rejection,
        )
        fixed_name = producer.index(
            "artifact/android_bounded_command.py runtime-avd-name",
            fixed_selection,
        )
        verification = producer.index(
            "artifact/android_device_proof.py verify-avd-home",
            fixed_name,
        )
        capability = producer.index(
            "artifact/android_bounded_command.py create-capability",
            verification,
        )
        emulator = producer.index("emulator-nodaemon", capability)
        self.assertLess(ambient_rejection, fixed_selection)
        self.assertLess(fixed_selection, fixed_name)
        self.assertLess(fixed_name, verification)
        self.assertLess(verification, capability)
        self.assertLess(capability, emulator)
        self.assertIn('export ANDROID_AVD_HOME', producer)
        self.assertIn('QPERIAPT_ANDROID_AVD is code-selected', producer)
        self.assertIn(
            'a script-owned proof AVD requires an explicit fixed '
            'QPERIAPT_ANDROID_ADB_PROFILE',
            producer,
        )
        self.assertNotIn('--avd-name', producer)
        self.assertNotIn('$HOME/.android/avd', producer)

    def test_private_server_launcher_preserves_exec_pid_without_bytecode_cache(
        self,
    ) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        root = artifact.parent
        producer = (artifact / "android-device-smoke.sh").read_text(encoding="utf-8")
        cache_assignment = producer.index(
            'ADB_PRIVATE_SERVER_PYTHON_CACHE="$ADB_PRIVATE_SERVER_DIRECTORY/python-cache"'
        )
        cache_precheck = producer.index(
            "private adb Python cache path already exists", cache_assignment
        )
        server_start = producer.index(
            '"$QPERIAPT_PYTHON" -I -S -B -X '
            '"pycache_prefix=$ADB_PRIVATE_SERVER_PYTHON_CACHE"'
        )
        server_pid = producer.index("ADB_PRIVATE_SERVER_PID=$!", server_start)
        cache_postcheck = producer.index(
            "private adb Python cache path appeared during server launch", server_pid
        )
        socket_verification = producer.index(
            "verify-private-adb-socket", cache_postcheck
        )
        self.assertLess(cache_assignment, cache_precheck)
        self.assertLess(cache_precheck, server_start)
        self.assertLess(server_start, server_pid)
        self.assertLess(server_pid, cache_postcheck)
        self.assertLess(cache_postcheck, socket_verification)
        self.assertIn(
            '"$QPERIAPT_PYTHON_BOOTSTRAP" '
            "artifact/android_bounded_command.py server-nodaemon",
            producer[server_start:server_pid],
        )
        self.assertIn(
            'server-nodaemon \\\n\t--run-id "$RUN_ID" \\\n\t>"$DIST/adb-server.log" 2>&1 &\n',
            producer[server_start:server_pid],
        )
        self.assertIn(
            "artifact/android_bounded_command.py server-nodaemon \\\n"
            '\t--run-id "$RUN_ID" \\\n'
            '\t>"$DIST/adb-server.log" 2>&1 &\n'
            "ADB_PRIVATE_SERVER_PID=$!",
            producer,
        )
        self.assertNotIn(
            "PYTHONPATH=artifact python3 "
            "artifact/android_bounded_command.py server-nodaemon",
            producer,
        )
        self.assertEqual(
            producer.count(
                'if [ -e "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ] || '
                '[ -L "$ADB_PRIVATE_SERVER_PYTHON_CACHE" ]; then'
            ),
            2,
        )

        with tempfile.TemporaryDirectory() as temporary:
            cache_prefix = pathlib.Path(temporary) / "python-cache"
            shell = r"""set -eu
ROOT=$1
cache_prefix=$2
. "$ROOT/artifact/python-env.sh"
"$QPERIAPT_PYTHON" -I -S -B -X "pycache_prefix=$cache_prefix" \
    "$QPERIAPT_PYTHON_BOOTSTRAP" -c "$3" &
launcher=$!
printf 'launcher=%s\n' "$launcher"
wait "$launcher"
"""
            exec_chain = """import os
import sys

prefix = sys.pycache_prefix
print(f"python={os.getpid()}", flush=True)
print(f"prefix={prefix}", flush=True)
print(f"python_cache={'present' if os.path.lexists(prefix) else 'absent'}", flush=True)
final_command = (
    'printf "final=%s\\n" "$$"; '
    'if [ -e "$CACHE_PREFIX" ] || [ -L "$CACHE_PREFIX" ]; then '
    'printf "final_cache=present\\n"; '
    'else printf "final_cache=absent\\n"; fi'
)
os.execve(
    "/bin/sh",
    ["/bin/sh", "-c", final_command],
    {"CACHE_PREFIX": prefix},
)
"""
            process = subprocess.Popen(
                [
                    "/bin/sh",
                    "-c",
                    shell,
                    "qperiapt-private-server-pid-test",
                    str(root),
                    str(cache_prefix),
                    exec_chain,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                self.fail(f"private server PID exec-chain test timed out: {exc}")
            self.assertEqual(process.returncode, 0)
            self.assertEqual(stderr, "")
            pairs: list[tuple[str, str]] = []
            for line in stdout.splitlines():
                self.assertRegex(line, r"^[a-z_]+=[^\r\n]+$")
                pairs.append(tuple(line.split("=", 1)))
            identities = dict(pairs)
            self.assertEqual(len(pairs), len(identities))
            self.assertEqual(
                set(identities),
                {
                    "launcher",
                    "python",
                    "prefix",
                    "python_cache",
                    "final",
                    "final_cache",
                },
            )
            self.assertEqual(identities["launcher"], identities["python"])
            self.assertEqual(identities["python"], identities["final"])
            self.assertEqual(identities["prefix"], str(cache_prefix))
            self.assertEqual(identities["python_cache"], "absent")
            self.assertEqual(identities["final_cache"], "absent")
            self.assertFalse(os.path.lexists(cache_prefix))

    def test_direct_private_server_launcher_ignores_adjacent_bytecode(self) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as temporary:
            fixture_root = pathlib.Path(temporary) / "fixture"
            fixture_artifact = fixture_root / "artifact"
            fixture_artifact.mkdir(parents=True)
            bootstrap = fixture_artifact / "python_bootstrap.py"
            shutil.copy2(artifact / "python_bootstrap.py", bootstrap)
            module = fixture_artifact / "launcher_probe.py"
            runner = fixture_artifact / "runner.py"
            hostile_source = 'VALUE = "hostile"\n'
            clean_source = 'VALUE = "source_"\n'
            self.assertEqual(len(hostile_source), len(clean_source))
            module.write_text(hostile_source, encoding="utf-8")
            source_metadata = module.stat()
            bytecode = (
                module.parent
                / "__pycache__"
                / f"{module.stem}.{sys.implementation.cache_tag}.pyc"
            )
            bytecode.parent.mkdir()
            py_compile.compile(
                str(module),
                cfile=str(bytecode),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            )
            module.write_text(clean_source, encoding="utf-8")
            os.utime(
                module,
                ns=(source_metadata.st_atime_ns, source_metadata.st_mtime_ns),
            )
            runner.write_text(
                "from launcher_probe import VALUE\nprint(VALUE)\n",
                encoding="utf-8",
            )

            baseline = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(bootstrap), str(runner)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(baseline.stdout, "hostile\n")
            self.assertEqual(baseline.stderr, "")

            private_directory = fixture_root / "private"
            private_directory.mkdir(mode=0o700)
            cache_prefix = private_directory / "python-cache"
            hardened = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-X",
                    f"pycache_prefix={cache_prefix}",
                    str(bootstrap),
                    str(runner),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(hardened.stdout, "source_\n")
            self.assertEqual(hardened.stderr, "")
            self.assertFalse(os.path.lexists(cache_prefix))

    def test_android_release_entrypoints_default_to_stable_sdk_contract(self) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        for name in ("android-aar.sh", "android-device-smoke.sh"):
            with self.subTest(entrypoint=name):
                source = (artifact / name).read_text(encoding="utf-8")
                self.assertIn(
                    'ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-"$ANDROID_SDK/platforms/android-35"}',
                    source,
                )
                self.assertNotIn(
                    "ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-$(choose_highest_child",
                    source,
                )
                self.assertIn(
                    'ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-"$ANDROID_SDK/build-tools/36.0.0"}',
                    source,
                )
                self.assertNotIn(
                    "ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-$(choose_highest_child",
                    source,
                )

        producer = (artifact / "android-device-smoke.sh").read_text(encoding="utf-8")
        adapter = (artifact / "android_bounded_command.py").read_text(encoding="utf-8")
        self.assertIn('"-no-snapshot",', adapter)
        self.assertIn("ANDROID_RELEASE_BUILD_TOOLS=36.0.0", producer)
        self.assertIn(
            'ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-"$ANDROID_SDK/build-tools/36.0.0"}',
            producer,
        )
        self.assertIn(
            'if [ "$ANDROID_RELEASE_MODE" = "1" ] && [ "$ANDROID_BUILD_TOOLS" != "$EXPECTED_RELEASE_BUILD_TOOLS" ]; then',
            producer,
        )

    def test_producer_captures_only_the_smoke_log_tag(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("capture_app_logcat()", producer)
        self.assertIn("android_command capture-logcat", producer)
        adapter = (
            pathlib.Path(__file__).resolve().parent / "android_bounded_command.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"logcat",', adapter)
        self.assertIn('"-T",\n            _device_epoch(layout),', adapter)
        self.assertIn('"QPeriaptSmoke:*",\n            "*:S",', adapter)
        self.assertIn('needle = f"run-id={run_id}"', producer)
        self.assertNotIn('"$ADB" -s "$SERIAL" logcat -d >', producer)
        self.assertNotIn("logcat -c", producer)

    def test_result_verifier_rejects_unrelated_logcat_data(self) -> None:
        run_id = "a" * 32
        result_txt = self.root / "result.txt"
        result_json = self.root / "result.json"
        logcat = self.root / "logcat.txt"
        result_txt.write_text(
            android_device_proof.expected_marker(run_id) + "\n", encoding="utf-8"
        )
        result_json.write_text(
            '{"schema":1,"status":"pass","run_id":"'
            + run_id
            + '","test_count":3,"passed_tests":['
            '"runtimeMetadataMatches",'
            '"signedPolicyDecisionIsExactAndFailClosed",'
            '"osRandomPolicyRoundtripAndWipes"]}\n',
            encoding="utf-8",
        )
        paths = {
            "result_txt": result_txt,
            "result_json": result_json,
            "logcat": logcat,
        }
        valid_line = (
            f"I/QPeriaptSmoke: QPERIAPT_ANDROID_DEVICE_PASS run-id={run_id} tests=3\n"
        )
        logcat.write_text(valid_line, encoding="utf-8")
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "--------- beginning of main\n"
            "I/QPeriaptSmoke( 123): QPERIAPT_ANDROID_DEVICE_PASS "
            f"run-id={run_id} tests=3\n",
            encoding="utf-8",
        )
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            valid_line + "I/OtherApplication: private data\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/QPeriaptSmoke: QPERIAPT_ANDROID_DEVICE_PASS "
            f"run-id={'b' * 32} tests=3\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "another run"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "exactly one run-bound PASS"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/OtherApplication: mentions QPeriaptSmoke but is unrelated\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)

    def test_private_directory_canonicalization_accepts_only_aliases_above_leaf(
        self,
    ) -> None:
        physical_parent = self.root / "physical-parent"
        private_directory = physical_parent / "private"
        private_directory.mkdir(parents=True, mode=0o700)
        private_directory.chmod(0o700)
        alias_parent = self.root / "alias-parent"
        try:
            alias_parent.symlink_to(physical_parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"platform cannot create a directory symlink: {exc}")

        resolved = android_device_proof.canonical_private_directory(
            alias_parent / "private", "test private directory"
        )
        self.assertEqual(resolved, private_directory.resolve(strict=True))
        self.assertTrue(stat.S_ISDIR(resolved.lstat().st_mode))

        leaf_alias = self.root / "private-leaf-alias"
        leaf_alias.symlink_to(private_directory, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "must be a non-symlink directory"):
            android_device_proof.canonical_private_directory(
                leaf_alias, "test private directory"
            )

    def test_bundle_manifest_binds_exact_fixed_file_set(self) -> None:
        bundle_root = self.root / "bundle"
        proof = complete_proof_shape()
        payloads = {
            key: (
                android_device_proof.canonical_json(proof)
                if key == "proof"
                else f"evidence-{key}\n".encode("utf-8")
            )
            for key in android_device_proof.BUNDLE_FILE_PATHS
        }
        records = {}
        for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items():
            path = bundle_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payloads[key])
            records[key] = {
                "bytes": len(payloads[key]),
                "path": relative,
                "sha256": android_device_proof.sha256_bytes(payloads[key]),
            }
        manifest = {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": 1_700_000_000,
            "git_commit": proof["git_commit"],
            "run_id": proof["run_id"],
            "release_candidate_mode": False,
            "device": {
                key: proof["device"][key] for key in ("kind", "abi", "page_size", "sdk")
            },
            "raw_serial_recorded": False,
            "files": records,
        }
        selected, parsed_proof = android_device_proof.verify_bundle_manifest(
            bundle_root,
            manifest,
            archive_mtime=1_700_000_000,
        )
        self.assertEqual(set(android_device_proof.BUNDLE_FILE_PATHS), set(selected))
        self.assertEqual(proof, parsed_proof)
        self.assertNotIn(
            "keystore", "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values())
        )

        missing_sdk = copy.deepcopy(manifest)
        del missing_sdk["device"]["sdk"]
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                missing_sdk,
                archive_mtime=1_700_000_000,
            )

        wrong_sdk = copy.deepcopy(manifest)
        wrong_sdk["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                wrong_sdk,
                archive_mtime=1_700_000_000,
            )

        extra_device_field = copy.deepcopy(manifest)
        extra_device_field["device"]["model"] = "unbound"
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                extra_device_field,
                archive_mtime=1_700_000_000,
            )

        tampered_proof = copy.deepcopy(proof)
        tampered_proof["device"]["sdk"] = 34
        proof_path = selected["proof"]
        proof_path.write_bytes(android_device_proof.canonical_json(tampered_proof))
        cross_tamper = copy.deepcopy(manifest)
        cross_tamper["files"]["proof"] = android_device_proof.bundle_file_record(
            proof_path,
            android_device_proof.BUNDLE_FILE_PATHS["proof"],
        )
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                cross_tamper,
                archive_mtime=1_700_000_000,
            )
        proof_path.write_bytes(android_device_proof.canonical_json(proof))

        selected["logcat"].write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "bundled evidence bytes differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                manifest,
                archive_mtime=1_700_000_000,
            )

    def _bundle_for_proof(
        self, bundle_root: pathlib.Path, proof: dict
    ) -> dict:
        file_paths = android_device_proof.bundle_file_paths(proof)
        payloads = {
            key: (
                android_device_proof.canonical_json(proof)
                if key == "proof"
                else f"evidence-{key}\n".encode("utf-8")
            )
            for key in file_paths
        }
        records = {}
        for key, relative in file_paths.items():
            path = bundle_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payloads[key])
            records[key] = {
                "bytes": len(payloads[key]),
                "path": relative,
                "sha256": android_device_proof.sha256_bytes(payloads[key]),
            }
        return {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": 1_700_000_000,
            "git_commit": proof["git_commit"],
            "run_id": proof["run_id"],
            "release_candidate_mode": proof["release_candidate_mode"],
            "device": {
                key: proof["device"][key]
                for key in ("kind", "abi", "page_size", "sdk")
            },
            "raw_serial_recorded": False,
            "files": records,
        }

    def test_release_bundle_accepts_physical_device_shape(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        proof["device"]["kind"] = "physical"
        proof["device"]["page_size"] = 4096
        proof["device"]["sdk"] = 36
        proof["emulator_control"] = None
        proof["paths"] = {
            key: value
            for key, value in proof["paths"].items()
            if key not in android_device_proof.EMULATOR_CONTROL_PATH_KEYS
        }
        bundle_root = self.root / "physical-release-bundle"
        manifest = self._bundle_for_proof(bundle_root, proof)
        selected, parsed_proof = android_device_proof.verify_bundle_manifest(
            bundle_root,
            manifest,
            archive_mtime=1_700_000_000,
        )
        self.assertEqual(parsed_proof["device"]["page_size"], 4096)
        self.assertEqual(parsed_proof["device"]["sdk"], 36)
        self.assertIs(parsed_proof["release_candidate_mode"], True)

    def test_release_bundle_still_pins_emulator_device_shape(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        proof["device"]["page_size"] = 4096
        bundle_root = self.root / "emulator-release-bundle"
        manifest = self._bundle_for_proof(bundle_root, proof)
        with self.assertRaisesRegex(
            SystemExit, "not API 35 / 16 KiB"
        ):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                manifest,
                archive_mtime=1_700_000_000,
            )

    @unittest.skipUnless(os.name == "posix", "descriptor-safe staging is POSIX-only")
    def test_private_bundle_staging_is_no_replace_and_archive_stays_public(
        self,
    ) -> None:
        stage = self.root / "private-bundle-stage"
        stage.mkdir(mode=0o700)
        staged = stage / "evidence" / "proof.json"
        payload = b"private Android evidence\n"

        previous_umask = os.umask(0)
        try:
            android_device_proof.write_private_bundle_stage_file(staged, payload)
        finally:
            os.umask(previous_umask)

        metadata = staged.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_uid, os.geteuid())
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(staged.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(staged.parent.stat().st_mode), 0o700)

        with self.assertRaisesRegex(SystemExit, "cannot stage Android evidence"):
            android_device_proof.write_private_bundle_stage_file(staged, b"replacement")
        self.assertEqual(staged.read_bytes(), payload)

        victim = self.root / "symlink-victim.txt"
        victim.write_bytes(b"unchanged\n")
        symlink_leaf = stage / "evidence" / "symlink.json"
        symlink_leaf.symlink_to(victim)
        with self.assertRaisesRegex(SystemExit, "cannot stage Android evidence"):
            android_device_proof.write_private_bundle_stage_file(
                symlink_leaf, b"replacement"
            )
        self.assertEqual(victim.read_bytes(), b"unchanged\n")
        symlink_leaf.unlink()

        archive_parent = self.root.resolve(strict=True)
        private_bundle = archive_parent / "private-source.zip"
        private_audit = android_device_proof.create_zip(
            stage,
            private_bundle,
            root_name="android-evidence-test",
            mtime=1_700_000_000,
        )
        member = next(
            entry
            for entry in private_audit.entries
            if entry.path == "android-evidence-test/evidence/proof.json"
        )
        self.assertEqual(member.mode, 0o644)
        self.assertEqual(stat.S_IMODE(private_bundle.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "descriptor-safe staging is POSIX-only")
    def test_private_bundle_staging_failure_removes_partial_file(self) -> None:
        stage = self.root / "failed-private-bundle-stage"
        stage.mkdir(mode=0o700)
        staged = stage / "evidence" / "proof.json"
        with (
            mock.patch.object(os, "fsync", side_effect=OSError("injected fsync failure")),
            self.assertRaisesRegex(SystemExit, "injected fsync failure"),
        ):
            android_device_proof.write_private_bundle_stage_file(staged, b"partial")
        self.assertFalse(os.path.lexists(staged))

        with (
            mock.patch.object(
                android_device_proof,
                "_reject_macos_allow_acl",
                side_effect=[None, SystemExit("error: injected allow ACL")],
            ),
            mock.patch.object(
                os, "unlink", side_effect=OSError("injected unlink failure")
            ),
            self.assertRaisesRegex(
                SystemExit,
                "injected allow ACL; Android evidence staging cleanup also failed: "
                "partial-file cleanup failed: injected unlink failure",
            ),
        ):
            android_device_proof.write_private_bundle_stage_file(staged, b"partial")
        self.assertTrue(staged.exists())
        staged.unlink()

        with (
            mock.patch.object(
                android_device_proof,
                "_reject_macos_allow_acl",
                side_effect=[None, SystemExit("error: injected allow ACL")],
            ),
            self.assertRaisesRegex(SystemExit, "injected allow ACL"),
        ):
            android_device_proof.write_private_bundle_stage_file(staged, b"partial")
        self.assertFalse(os.path.lexists(staged))

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_private_bundle_staging_rejects_inherited_allow_acl(self) -> None:
        stage = self.root / "acl-private-bundle-stage"
        stage.mkdir(mode=0o700)
        subprocess.run(
            [
                "/bin/chmod",
                "+a",
                "everyone allow readattr,file_inherit,directory_inherit",
                str(stage),
            ],
            check=True,
        )
        staged = stage / "evidence" / "proof.json"
        try:
            with self.assertRaisesRegex(SystemExit, "allow ACL is forbidden"):
                android_device_proof.write_private_bundle_stage_file(
                    staged, b"private"
                )
            self.assertFalse(os.path.lexists(staged))
        finally:
            subprocess.run(["/bin/chmod", "-RN", str(stage)], check=True)

    def test_physical_bundle_omits_emulator_only_receipts(self) -> None:
        bundle_root = self.root / "physical-bundle"
        proof = complete_proof_shape()
        proof["device"]["kind"] = "physical"
        proof["emulator_control"] = None
        proof["paths"] = {
            key: proof["paths"][key]
            for key in android_device_proof.BASE_PROOF_PATH_KEYS
        }
        file_paths = android_device_proof.bundle_file_paths(proof)
        self.assertEqual(file_paths, android_device_proof.BASE_BUNDLE_FILE_PATHS)
        self.assertTrue(
            set(android_device_proof.EMULATOR_CONTROL_PATH_KEYS).isdisjoint(file_paths)
        )

        records = {}
        for key, relative in file_paths.items():
            payload = (
                android_device_proof.canonical_json(proof)
                if key == "proof"
                else f"physical-evidence-{key}\n".encode("utf-8")
            )
            path = bundle_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            records[key] = android_device_proof.bundle_file_record(path, relative)
        manifest = {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": 1_700_000_000,
            "git_commit": proof["git_commit"],
            "run_id": proof["run_id"],
            "release_candidate_mode": proof["release_candidate_mode"],
            "device": {
                key: proof["device"][key]
                for key in ("kind", "abi", "page_size", "sdk")
            },
            "raw_serial_recorded": False,
            "files": records,
        }
        selected, parsed_proof = android_device_proof.verify_bundle_manifest(
            bundle_root,
            manifest,
            archive_mtime=1_700_000_000,
        )
        self.assertEqual(set(selected), set(android_device_proof.BASE_BUNDLE_FILE_PATHS))
        self.assertEqual(parsed_proof, proof)

    def test_published_v1_verifier_accepts_a_real_schema3_archive(self) -> None:
        self.assertEqual(
            PUBLISHED_V1_SCHEMA,
            android_device_proof.PUBLISHED_BUNDLE_SCHEMA_VERSION,
        )
        self.assertEqual(
            PUBLISHED_V1_PROOF_SCHEMA,
            android_device_proof.PUBLISHED_ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            PUBLISHED_V1_ROOT,
            android_device_proof.PUBLISHED_BUNDLE_ROOT_NAME,
        )
        self.assertEqual(
            PUBLISHED_V1_MANIFEST_PATH,
            android_device_proof.PUBLISHED_BUNDLE_MANIFEST_PATH,
        )
        self.assertEqual(
            PUBLISHED_V1_KIND,
            android_device_proof.PUBLISHED_BUNDLE_KIND,
        )
        self.assertEqual(
            PUBLISHED_V1_FILE_PATHS,
            android_device_proof.PUBLISHED_BUNDLE_FILE_PATHS,
        )
        self.assertEqual(
            PUBLISHED_V1_ARCHIVE_ENTRIES,
            android_device_proof.PUBLISHED_BUNDLE_ARCHIVE_ENTRIES,
        )
        self.assertEqual(
            PUBLISHED_V1_MANIFEST_FIELDS,
            android_device_proof.PUBLISHED_BUNDLE_MANIFEST_FIELDS,
        )
        self.assertEqual(
            PUBLISHED_V1_FILE_RECORD_FIELDS,
            android_device_proof.PUBLISHED_BUNDLE_FILE_RECORD_FIELDS,
        )
        self.assertEqual(
            PUBLISHED_V1_PROOF_FIELDS,
            android_device_proof.PUBLISHED_PROOF_FIELDS,
        )
        self.assertEqual(
            PUBLISHED_V1_RESULT_FIELDS,
            android_device_proof.PUBLISHED_PROOF_RESULT_FIELDS,
        )
        self.assertEqual(
            PUBLISHED_V1_ARTIFACT_FIELDS,
            android_device_proof.PUBLISHED_PROOF_ARTIFACT_FIELDS,
        )
        self.assertEqual(
            PUBLISHED_V1_ARTIFACT_LINKS,
            android_device_proof.PUBLISHED_PROOF_ARTIFACT_LINKS,
        )
        self.assertEqual(
            PUBLISHED_V1_EXPECTED_TESTS,
            android_device_proof.PUBLISHED_EXPECTED_TESTS,
        )
        self.assertEqual(
            PUBLISHED_V1_BUNDLE_DEVICE,
            android_device_proof.PUBLISHED_BUNDLE_DEVICE,
        )
        self.assertEqual(
            PUBLISHED_V1_PROOF_DEVICE,
            android_device_proof.PUBLISHED_PROOF_DEVICE,
        )
        self.assertEqual(
            PUBLISHED_V1_PROOF_PATHS,
            android_device_proof.PUBLISHED_PROOF_PATHS,
        )
        self.assertEqual(
            PUBLISHED_V1_RUN_ID,
            android_device_proof.PUBLISHED_ANDROID_RUNTIME_RUN_ID,
        )
        self.assertEqual(
            PUBLISHED_V1_SOURCE_DATE_EPOCH,
            android_device_proof.PUBLISHED_ANDROID_RUNTIME_SOURCE_DATE_EPOCH,
        )
        self.assertEqual(PUBLISHED_V1_TAG_COMMIT, android_device_proof.TAG_COMMIT)
        self.assertEqual(
            PUBLISHED_V1_SOURCE_TREE_SHA256,
            android_device_proof.CANONICAL_SOURCE_TREE_SHA256,
        )
        fixture_root = self.root / "published-v1-valid"
        fixture_root.mkdir()
        bundle, bundle_sha256, manifest_sha256, proof_sha256 = (
            build_published_runtime_bundle_v1_fixture(fixture_root)
        )
        observed, manifest, proof = (
            android_device_proof._verify_published_runtime_bundle_v1_with_digests(
                bundle,
                expected_bundle_sha256=bundle_sha256,
                expected_manifest_sha256=manifest_sha256,
                expected_proof_sha256=proof_sha256,
            )
        )
        self.assertEqual(bundle_sha256, observed)
        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual(3, proof["schema"])

    def test_current_and_published_bundle_verifiers_do_not_auto_dispatch(self) -> None:
        fixture_root = self.root / "published-v1-no-dispatch"
        fixture_root.mkdir()
        bundle, bundle_sha256, _, _ = build_published_runtime_bundle_v1_fixture(
            fixture_root
        )
        with self.assertRaisesRegex(SystemExit, "selector differs"):
            android_device_proof.verify_published_runtime_bundle_v1(
                bundle,
                expected_bundle_sha256=bundle_sha256,
            )
        with self.assertRaisesRegex(SystemExit, "archive verification failed"):
            android_device_proof.verify_runtime_bundle(
                root=self.root,
                bundle=bundle,
                expected_bundle_sha256=bundle_sha256,
                llvm_nm=self.root / "llvm-nm",
                llvm_readelf=self.root / "llvm-readelf",
                apksigner=self.root / "apksigner",
                zipalign=self.root / "zipalign",
                expected_device_kind="emulator",
                expected_device_abi="arm64-v8a",
                expected_page_size=16_384,
                expected_device_sdk=35,
                require_release_mode=True,
                allow_dirty_proof=False,
                forbidden_text=[],
            )

    def test_published_v1_verifier_does_not_depend_on_current_shapes(self) -> None:
        fixture_root = self.root / "published-v1-current-drift"
        fixture_root.mkdir()
        bundle, bundle_sha256, manifest_sha256, proof_sha256 = (
            build_published_runtime_bundle_v1_fixture(fixture_root)
        )
        with (
            mock.patch.object(android_device_proof, "BUNDLE_KIND", "current.changed"),
            mock.patch.object(android_device_proof, "BUNDLE_MANIFEST_PATH", "NEW.json"),
            mock.patch.object(android_device_proof, "BASE_BUNDLE_FILE_PATHS", {}),
            mock.patch.object(android_device_proof, "PROOF_FIELDS", frozenset()),
            mock.patch.object(
                android_device_proof, "PROOF_RESULT_FIELDS", frozenset()
            ),
            mock.patch.object(
                android_device_proof, "PROOF_ARTIFACT_FIELDS", frozenset()
            ),
            mock.patch.object(android_device_proof, "EXPECTED_TESTS", ["future"]),
            mock.patch.object(android_device_proof, "ANDROID_RELEASE_SDK", 999),
        ):
            observed, manifest, proof = (
                android_device_proof._verify_published_runtime_bundle_v1_with_digests(
                    bundle,
                    expected_bundle_sha256=bundle_sha256,
                    expected_manifest_sha256=manifest_sha256,
                    expected_proof_sha256=proof_sha256,
                )
            )
        self.assertEqual(bundle_sha256, observed)
        self.assertEqual(PUBLISHED_V1_SCHEMA, manifest["schema_version"])
        self.assertEqual(PUBLISHED_V1_PROOF_SCHEMA, proof["schema"])

    def test_published_v1_verifier_rejects_schema_and_root_confusion(self) -> None:
        cases = (
            ("bundle-schema2", {"bundle_schema": 2}, "identity differs"),
            ("proof-schema5", {"proof_schema": 5}, "proof identity differs"),
            (
                "current-root",
                {"root_name": android_device_proof.BUNDLE_ROOT_NAME},
                "bundle is invalid",
            ),
        )
        for label, overrides, message in cases:
            with self.subTest(label=label):
                fixture_root = self.root / f"published-v1-{label}"
                fixture_root.mkdir()
                bundle, bundle_sha256, manifest_sha256, proof_sha256 = (
                    build_published_runtime_bundle_v1_fixture(
                        fixture_root, **overrides
                    )
                )
                with self.assertRaisesRegex(SystemExit, message):
                    android_device_proof._verify_published_runtime_bundle_v1_with_digests(
                        bundle,
                        expected_bundle_sha256=bundle_sha256,
                        expected_manifest_sha256=manifest_sha256,
                        expected_proof_sha256=proof_sha256,
                    )

    def test_proof_path_inventory_rejects_extra_dependencies(self) -> None:
        proof = complete_proof_shape()
        paths = proof["paths"]
        android_device_proof.proof_path_fields(proof)
        paths["keystore"] = "target/debug.keystore"
        with self.assertRaisesRegex(SystemExit, "path fields differ"):
            android_device_proof.proof_path_fields(proof)

    def test_unique_run_layout_rejects_cross_run_runtime_artifacts(self) -> None:
        run_id = "a" * 32
        proof = complete_proof_shape()
        proof["run_id"] = run_id
        proof_path = (
            self.root
            / "target"
            / android_device_proof.ANDROID_RUNS_ROOT_LEAF
            / run_id
            / "proof"
            / android_device_proof.ANDROID_PROOF_LEAF
        ).resolve()
        proof_root = proof_path.parent
        proof_root.mkdir(parents=True, mode=0o700)
        (proof_root.parent.parent).chmod(0o700)
        proof_root.parent.chmod(0o700)
        proof_root.chmod(0o700)
        proof_path.write_text("{}\n", encoding="utf-8")
        proof_path.chmod(0o600)
        paths = {
            "aar": self.root / proof["paths"]["aar"],
            "aar_manifest": self.root / proof["paths"]["aar_manifest"],
            "smoke_apk": proof_root / "qperiapt-android-smoke.apk",
            "apksigner_verify": proof_root / "apksigner-verify.txt",
            "zipalign_verify": proof_root / "zipalign-verify.txt",
            "result_txt": proof_root / "qperiapt-android-device-result.txt",
            "result_json": proof_root / "qperiapt-android-device-result.json",
            "logcat": proof_root / "logcat.txt",
        }
        paths.update(
            {
                android_device_proof.ADB_ISOLATION_PATH_KEY_BY_CHECKPOINT[
                    checkpoint
                ]: proof_root
                / android_device_proof.ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
                for checkpoint in android_device_proof.ADB_ISOLATION_CHECKPOINTS
            }
        )
        paths["emulator_routing"] = (
            proof_root / android_device_proof.EMULATOR_ROUTING_RECEIPT_LEAF
        )
        for name in (
            "smoke_apk",
            "apksigner_verify",
            "zipalign_verify",
            "result_txt",
            "result_json",
            "logcat",
            *android_device_proof.EMULATOR_CONTROL_PATH_KEYS,
        ):
            paths[name].write_bytes(b"fixture\n")
            paths[name].chmod(0o600)
        android_device_proof.validate_selected_run_layout(
            self.root,
            proof_path,
            proof,
            paths,
            require_unique_run=True,
        )
        for name in (
            "smoke_apk",
            "apksigner_verify",
            "zipalign_verify",
            "result_txt",
            "result_json",
            "logcat",
        ):
            with self.subTest(name=name):
                crossed = dict(paths)
                crossed[name] = (
                    crossed[name].parent.parent.parent
                    / ("b" * 32)
                    / "proof"
                    / crossed[name].name
                )
                with self.assertRaises(SystemExit):
                    android_device_proof.validate_selected_run_layout(
                        self.root,
                        proof_path,
                        proof,
                        crossed,
                        require_unique_run=True,
                    )

        paths["logcat"].chmod(0o640)
        with self.assertRaisesRegex(SystemExit, "mode-0600 regular file"):
            android_device_proof.validate_selected_run_layout(
                self.root,
                proof_path,
                proof,
                paths,
                require_unique_run=True,
            )
        paths["logcat"].chmod(0o600)
        proof_root.chmod(0o750)
        with self.assertRaisesRegex(SystemExit, "must not be accessible"):
            android_device_proof.validate_selected_run_layout(
                self.root,
                proof_path,
                proof,
                paths,
                require_unique_run=True,
            )
        proof_root.chmod(0o700)

        wrong_id = dict(proof)
        wrong_id["run_id"] = "b" * 32
        with self.assertRaises(SystemExit):
            android_device_proof.validate_selected_run_layout(
                self.root,
                proof_path,
                wrong_id,
                paths,
                require_unique_run=True,
            )


if __name__ == "__main__":
    unittest.main()
