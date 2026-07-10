#!/usr/bin/env python3
"""Verify Q-Periapt Android runtime proof metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import zipfile
from typing import Any


SCHEMA_VERSION = 1
PASS_MARKER = "QPERIAPT_ANDROID_DEVICE_PASS"
FAIL_MARKER = "QPERIAPT_ANDROID_DEVICE_FAIL"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_ANDROID_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60

EXPECTED_TESTS = [
    "runtimeMetadataMatches",
    "combineReferenceVectors",
    "sharedVectorDecapsulates",
    "sharedVectorEncapsulates",
    "contextBoundRejectsEmptyContext",
    "compatXWingSeedKeypairRoundtrip",
    "signedPolicySelectsProfileAndRejectsRollbackAndTamper",
    "uint32ScalarsRejectNegativeAndOverflow",
]

SOURCE_INPUTS = {
    "android_device_smoke_script": "artifact/android-device-smoke.sh",
    "android_device_proof": "artifact/android_device_proof.py",
    "proof_to_byte": "artifact/proof-to-byte.sh",
    "android_aar_script": "artifact/android-aar.sh",
    "android_facade": "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java",
    "android_jni_adapter": "bindings/android/jni/qperiapt_jni.c",
    "contextbound_vectors": "bindings/contextbound-vectors.txt",
    "shared_vectors": "bindings/shared-test-vectors.json",
    "signed_policy_vectors": "bindings/signed-policy-vectors.json",
}

REQUIRED_NATIVE_ABIS = ("arm64-v8a", "x86_64", "armeabi-v7a", "x86")

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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def read_bytes(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(read_bytes(path))


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: cannot parse JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


def run_git(root: pathlib.Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args],
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot run git {' '.join(args)}: {exc}") from exc


def git_commit(root: pathlib.Path) -> str:
    commit = run_git(root, "rev-parse", "HEAD")
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, f"malformed git commit: {commit}")
    return commit


def source_tree_dirty(root: pathlib.Path) -> bool:
    return bool(run_git(root, "status", "--porcelain=v1", "--untracked-files=all"))


def verify_git_provenance(root: pathlib.Path, proof: dict[str, Any], allow_dirty_proof: bool) -> None:
    proof_commit = proof.get("git_commit")
    require(
        isinstance(proof_commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", proof_commit) is not None,
        "Android proof lacks a valid git_commit",
    )
    current_commit = git_commit(root)
    require(
        proof_commit == current_commit,
        f"Android proof was generated for git commit {proof_commit}, current commit is {current_commit}",
    )
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
    return parsed.astimezone(dt.timezone.utc)


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


def verify_source_hashes(root: pathlib.Path, proof: dict[str, Any]) -> None:
    expected = proof.get("source_hashes")
    require(isinstance(expected, dict), "proof lacks source_hashes")
    for name, rel in SOURCE_INPUTS.items():
        got = sha256_file(root / rel)
        require(expected.get(name + "_sha256") == got, f"source input changed since Android proof: {name}")


def verify_result_files(paths: dict[str, pathlib.Path], run_id: str) -> None:
    marker = expected_marker(run_id)
    marker_text = read_text(paths["result_txt"])
    require(marker_text == marker + "\n", f"Android result marker mismatch in {paths['result_txt']}")

    result = load_json(paths["result_json"])
    require(result.get("schema") == SCHEMA_VERSION, "Android result schema mismatch")
    require(result.get("status") == "pass", "Android result status is not pass")
    require(result.get("run_id") == run_id, "Android result run_id mismatch")
    require(result.get("test_count") == len(EXPECTED_TESTS), "Android result test_count mismatch")
    require(result.get("passed_tests") == EXPECTED_TESTS, "Android result passed_tests mismatch")

    logcat = read_text(paths["logcat"])
    for pattern in LOG_FATAL_PATTERNS:
        require(pattern not in logcat, f"Android logcat contains runtime failure marker: {pattern}")


def verify_artifact_hashes(paths: dict[str, pathlib.Path], proof: dict[str, Any]) -> None:
    artifacts = proof.get("artifacts")
    require(isinstance(artifacts, dict), "proof lacks artifacts")
    expected_hashes = {
        "aar_sha256": paths["aar"],
        "aar_manifest_sha256": paths["aar_manifest"],
        "smoke_apk_sha256": paths["smoke_apk"],
        "apksigner_verify_sha256": paths["apksigner_verify"],
        "logcat_sha256": paths["logcat"],
    }
    for key, path in expected_hashes.items():
        require(artifacts.get(key) == sha256_file(path), f"hash mismatch for {key}: {path}")

    result = proof.get("result")
    require(isinstance(result, dict), "proof lacks result")
    require(result.get("marker_sha256") == sha256_file(paths["result_txt"]), "result marker hash mismatch")
    require(result.get("json_sha256") == sha256_file(paths["result_json"]), "result JSON hash mismatch")
    require(result.get("status") == "pass", "proof result status is not pass")
    require(result.get("test_count") == len(EXPECTED_TESTS), "proof result test_count mismatch")
    require(result.get("passed_tests") == EXPECTED_TESTS, "proof result passed_tests mismatch")


def verify_native_hashes(paths: dict[str, pathlib.Path], proof: dict[str, Any]) -> None:
    artifacts = proof.get("artifacts")
    require(isinstance(artifacts, dict), "proof lacks artifacts")
    native = artifacts.get("native")
    require(isinstance(native, dict), "proof lacks native hashes")
    for abi in REQUIRED_NATIVE_ABIS:
        expected = native.get(abi)
        require(isinstance(expected, dict), f"proof lacks native hashes for {abi}")
        with zipfile.ZipFile(paths["aar"]) as zf:
            ffi = sha256_bytes(zf.read(f"jni/{abi}/libq_periapt_ffi.so"))
            jni = sha256_bytes(zf.read(f"jni/{abi}/libqperiapt_jni.so"))
        require(expected.get("ffi_so_sha256") == ffi, f"AAR ffi hash mismatch for {abi}")
        require(expected.get("jni_so_sha256") == jni, f"AAR JNI hash mismatch for {abi}")


def verify(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    proof_path = args.proof.resolve()
    require_under(proof_path, root / "target", "Android proof")
    proof = load_json(proof_path)

    require(proof.get("schema") == SCHEMA_VERSION, "Android proof schema mismatch")
    require(proof.get("device_runtime_proof") is True, "proof is not an Android runtime proof")
    require(proof.get("package_only") is False, "runtime proof must not be package_only")
    require(proof.get("package") == "dev.qperiapt.androidsmoke", "unexpected Android proof package")
    run_id = proof.get("run_id")
    require(isinstance(run_id, str), "proof run_id is missing")
    expected_marker(run_id)

    generated_at = parse_generated_at(proof.get("generated_at"))
    age_seconds = (dt.datetime.now(dt.timezone.utc) - generated_at).total_seconds()
    require(age_seconds >= 0, "Android proof generated_at is in the future")
    require(age_seconds <= args.max_age_seconds, f"Android proof is stale: {int(age_seconds)}s old")
    verify_git_provenance(root, proof, args.allow_dirty_proof)

    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks device metadata")
    require(device.get("raw_serial_recorded") is False, "proof must not record raw adb serial")
    require("serial" not in device, "proof must not include raw adb serial")
    kind = device.get("kind")
    require(kind in {"emulator", "physical"}, f"invalid Android device kind: {kind}")
    if args.expected_device_kind:
        require(kind == args.expected_device_kind, f"expected Android device kind {args.expected_device_kind}, got {kind}")

    rel_paths = proof.get("paths")
    require(isinstance(rel_paths, dict), "proof lacks artifact paths")
    paths = {name: target_path(root, rel_paths.get(name), name) for name in (
        "aar",
        "aar_manifest",
        "smoke_apk",
        "apksigner_verify",
        "result_txt",
        "result_json",
        "logcat",
    )}

    verify_source_hashes(root, proof)
    verify_result_files(paths, run_id)
    verify_artifact_hashes(paths, proof)
    verify_native_hashes(paths, proof)
    print("ANDROID_DEVICE_PROOF_VERIFY_PASS")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    verify_parser = sub.add_parser("verify", help="verify an Android runtime proof JSON")
    verify_parser.add_argument("--root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--proof", required=True, type=pathlib.Path)
    verify_parser.add_argument(
        "--max-age-seconds",
        type=validate_max_age_seconds,
        default=86400,
    )
    verify_parser.add_argument("--expected-device-kind", choices=["emulator", "physical"], default="")
    verify_parser.add_argument("--allow-dirty-proof", action="store_true")
    verify_parser.set_defaults(func=verify)
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
