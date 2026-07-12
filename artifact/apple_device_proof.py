#!/usr/bin/env python3
"""Emit and verify source-bound Q-Periapt physical Apple-device proof metadata."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import subprocess
from typing import Any

from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    JsonObjectSnapshot,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    git_commit as provenance_git_commit,
    require_commit_or_evidence_successor,
    source_tree_dirty as provenance_source_tree_dirty,
)
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)

SCHEMA_VERSION = 2
MATRIX_SCHEMA_VERSION = 3
MAX_APPLE_PROOF_BYTES = 4 * 1024 * 1024
MAX_APPLE_ARTIFACT_BYTES = 128 * 1024 * 1024
REQUIRED_MATRIX_LABEL_TO_TYPE = {"ipad": "iPad", "iphone": "iPhone"}
REQUIRED_MATRIX_TYPES = ("iPad", "iPhone")
PASS_MARKER = "QPERIAPT_DEVICE_PASS"
FAIL_MARKER = "QPERIAPT_DEVICE_FAIL"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
MAX_DEVICE_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_PROFILE_VALID_DAYS = 366
RELEASE_DEVICE_PROOF_MAX_AGE_SECONDS = 24 * 60 * 60
RELEASE_MIN_PROFILE_VALID_DAYS = 30

SOURCE_INPUTS = {
    "apple_device_smoke": "artifact/apple-device-smoke.sh",
    "apple_device_matrix": "artifact/apple-device-matrix.sh",
    "apple_device_xcode27_gate": "artifact/apple-device-xcode27-gate.sh",
    "apple_device_proof": "artifact/apple_device_proof.py",
    "proof_to_byte": "artifact/proof-to-byte.sh",
    "apple_device_project": "bindings/apple-device/project.yml",
    "apple_device_main": "bindings/apple-device/Sources/QPeriaptDeviceRunner/main.swift",
    "apple_device_smoke_swift": "bindings/apple-device/Sources/QPeriaptDeviceRunner/DeviceSmoke.swift",
    "swift_binding": "bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift",
    "swift_c_header": "bindings/swift/Sources/CQPeriapt/q_periapt.h",
    "shared_vectors": "bindings/shared-test-vectors.json",
    "combiner_vectors": "bindings/contextbound-vectors.txt",
    "signed_policy_vectors": "bindings/signed-policy-vectors.json",
}

APPLE_PROOF_FIELDS = {
    "app",
    "artifacts_sha256",
    "bundle_id",
    "checks",
    "developer_dir",
    "device",
    "device_id",
    "device_id_sha256",
    "generated_at",
    "git_commit",
    "linkage",
    "profile",
    "proof_source_tree_sha256",
    "run_id",
    "rustc_version",
    "schema_version",
    "source_inputs_sha256",
    "source_policy",
    "source_tree_dirty",
    "status",
    "swift_version",
    "xcode_version",
}
MATRIX_PROOF_FIELDS = {
    "devices",
    "generated_at",
    "git_commit",
    "proof_source_tree_sha256",
    "required_device_types",
    "schema_version",
    "source_inputs_sha256",
    "source_tree_dirty",
    "status",
}
MATRIX_ENTRY_FIELDS = {
    "build_log",
    "device_id_sha256",
    "device_result",
    "device_type",
    "label",
    "launch_log",
    "marketing_name",
    "os_build",
    "os_version",
    "prefix",
    "product_type",
    "proof",
    "proof_sha256",
    "run_id",
}


def read_bytes(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


def snapshot_file(path: pathlib.Path, label: str) -> FileSnapshot:
    try:
        return read_regular_snapshot(
            path,
            maximum=MAX_APPLE_ARTIFACT_BYTES,
            label=label,
        )
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc


def snapshot_text(snapshot: FileSnapshot, label: str) -> str:
    try:
        return snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"error: {label} is not UTF-8: {snapshot.path}") from exc


def parse_plist_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = plistlib.loads(data)
    except Exception as exc:  # plistlib raises several parse-specific exceptions.
        raise SystemExit(f"error: cannot parse plist {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"error: plist root is not a dictionary: {label}")
    return value


def load_plist(path: pathlib.Path) -> dict[str, Any]:
    snapshot = snapshot_file(path, f"plist {path}")
    return parse_plist_bytes(snapshot.data, str(path))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


def rooted_lexical_path(root: pathlib.Path, value: str | pathlib.Path) -> pathlib.Path:
    candidate = pathlib.Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    return pathlib.Path(os.path.abspath(candidate))


def device_runs_root(root: pathlib.Path) -> pathlib.Path:
    return root / "artifact" / "device-runs"


def validate_max_age_seconds(value: int) -> int:
    require(
        0 < value <= MAX_DEVICE_PROOF_AGE_SECONDS,
        f"max-age-seconds must be between 1 and {MAX_DEVICE_PROOF_AGE_SECONDS}: {value}",
    )
    return value


def validate_min_profile_valid_days(value: int) -> int:
    require(
        0 <= value <= MAX_PROFILE_VALID_DAYS,
        f"min-profile-valid-days must be between 0 and {MAX_PROFILE_VALID_DAYS}: {value}",
    )
    return value


def require_release_policy(
    max_age_seconds: int,
    allow_dirty_proof: bool,
    *,
    min_profile_valid_days: int | None = None,
) -> None:
    if allow_dirty_proof:
        return
    require(
        max_age_seconds == RELEASE_DEVICE_PROOF_MAX_AGE_SECONDS,
        "release verification fixes Apple proof freshness to 86400 seconds",
    )
    if min_profile_valid_days is not None:
        require(
            min_profile_valid_days >= RELEASE_MIN_PROFILE_VALID_DAYS,
            "release verification requires at least a 30-day profile-validity policy",
        )


def developer_mode_enabled(state: dict[str, Any]) -> bool:
    status = state.get("developerModeStatus")
    if not isinstance(status, dict):
        return False
    enabled = status.get("enabled")
    if not isinstance(enabled, dict):
        return False
    return enabled.get("mode") == 1


def expected_marker(run_id: str) -> str:
    require(bool(RUN_ID_RE.fullmatch(run_id)), f"invalid run id: {run_id}")
    return f"{PASS_MARKER} run-id={run_id}"


def marker_count(text: str, run_id: str) -> int:
    marker = expected_marker(run_id)
    return sum(1 for line in text.splitlines() if line.strip() == marker)


def require_marker_text(text: str, path: pathlib.Path, label: str, run_id: str) -> None:
    require(FAIL_MARKER not in text, f"{label} contains {FAIL_MARKER}: {path}")
    count = marker_count(text, run_id)
    require(count == 1, f"{label} must contain exactly one {expected_marker(run_id)}, found {count}: {path}")
    legacy_count = sum(1 for line in text.splitlines() if line.strip() == PASS_MARKER)
    require(legacy_count == 0, f"{label} contains legacy bare {PASS_MARKER}: {path}")


def require_marker(path: pathlib.Path, label: str, run_id: str) -> None:
    snapshot = snapshot_file(path, label)
    require_marker_text(snapshot_text(snapshot, label), path, label, run_id)


def require_clean_build_log_text(text: str, path: pathlib.Path) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        if re.search(r"(^|[^A-Za-z])(warning|error):", line, flags=re.IGNORECASE):
            raise SystemExit(f"error: Xcode build log is not clean at {path}:{line_no}: {line}")


def require_clean_build_log(path: pathlib.Path) -> None:
    snapshot = snapshot_file(path, "Xcode build log")
    require_clean_build_log_text(snapshot_text(snapshot, "Xcode build log"), path)


def run_line(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot run {' '.join(args)}: {exc}") from exc


def git_commit(root: pathlib.Path) -> str:
    try:
        return provenance_git_commit(root)
    except GitProvenanceError as exc:
        raise SystemExit(f"error: cannot inspect git commit: {exc}") from exc


def source_tree_dirty(root: pathlib.Path) -> bool:
    try:
        return provenance_source_tree_dirty(root)
    except GitProvenanceError as exc:
        raise SystemExit(f"error: cannot inspect git worktree status: {exc}") from exc


def verify_device_id_digest(proof: dict[str, Any], label: str) -> None:
    device_id = proof.get("device_id")
    declared = proof.get("device_id_sha256")
    require(isinstance(device_id, str) and bool(device_id), f"{label} lacks device_id")
    require(
        isinstance(declared, str) and SHA256_RE.fullmatch(declared) is not None,
        f"{label} lacks a valid device_id_sha256",
    )
    expected = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
    require(declared == expected, f"{label} device_id_sha256 does not bind device_id")


def current_source_tree_digest(root: pathlib.Path) -> str:
    """Return the claim-ledger gate's canonical source-input digest."""

    try:
        return canonical_tree_digest(root, repository_paths(root))
    except (LedgerError, OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot compute canonical source-input digest: {exc}") from exc


def freeze_source_snapshot(root: pathlib.Path) -> tuple[str, str]:
    """Capture a commit/digest pair while rejecting a concurrent commit transition."""

    commit_before = git_commit(root)
    digest = current_source_tree_digest(root)
    commit_after = git_commit(root)
    require(
        commit_before == commit_after,
        f"git commit changed while freezing Apple device source: {commit_before} -> {commit_after}",
    )
    return commit_before, digest


def require_source_snapshot_unchanged(
    root: pathlib.Path,
    expected_commit: str,
    expected_digest: str,
    label: str,
) -> None:
    """Fail closed if commit or canonical execution inputs differ from a pre-run freeze."""

    require(GIT_COMMIT_RE.fullmatch(expected_commit) is not None, f"{label} lacks a valid frozen git commit")
    require(SHA256_RE.fullmatch(expected_digest) is not None, f"{label} lacks a valid frozen source-input digest")
    current_commit = git_commit(root)
    require(
        current_commit == expected_commit,
        f"git commit changed while {label}: got {current_commit}, expected {expected_commit}",
    )
    current_digest = current_source_tree_digest(root)
    require(
        current_digest == expected_digest,
        f"canonical source-input tree changed while {label}: got {current_digest}, expected {expected_digest}",
    )


def verify_proof_schema(
    proof: dict[str, Any],
    label: str,
    expected_schema: int = SCHEMA_VERSION,
) -> None:
    require(type(proof.get("schema_version")) is int, f"{label} schema must be an integer")
    require(proof.get("schema_version") == expected_schema, f"{label} schema must be {expected_schema}")


def strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    require(not missing, f"{label} is missing fields: {sorted(missing)}")
    require(not extra, f"{label} has unknown fields: {sorted(extra)}")


def load_apple_json_snapshot(path: pathlib.Path, label: str) -> JsonObjectSnapshot:
    try:
        return load_json_object_snapshot(
            path,
            maximum=MAX_APPLE_PROOF_BYTES,
            label=label,
        )
    except EvidenceIOError as exc:
        raise SystemExit(f"error: {exc}") from exc


def verify_source_tree_digest(root: pathlib.Path, proof: dict[str, Any], label: str) -> None:
    expected = proof.get("proof_source_tree_sha256")
    require(
        isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
        f"{label} lacks a valid proof_source_tree_sha256",
    )
    current = current_source_tree_digest(root)
    require(
        current == expected,
        f"canonical source-input tree changed since {label}: got {current}, expected {expected}",
    )


def verify_git_provenance(root: pathlib.Path, proof: dict[str, Any], allow_dirty_proof: bool, label: str) -> None:
    commit = proof.get("git_commit")
    dirty = proof.get("source_tree_dirty")
    require(isinstance(commit, str) and GIT_COMMIT_RE.fullmatch(commit) is not None, f"{label} lacks git_commit")
    require(isinstance(dirty, bool), f"{label} lacks source_tree_dirty")
    try:
        require_commit_or_evidence_successor(root, commit)
    except GitProvenanceError as exc:
        require(False, f"{label} commit provenance failed: {exc}")
    current_dirty = source_tree_dirty(root)
    if not allow_dirty_proof:
        require(dirty is False, f"{label} was generated from a dirty source tree")
        require(current_dirty is False, f"{label} cannot be release-verified while the current source tree is dirty")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def normalize_datetime(value: Any, label: str) -> dt.datetime:
    require(isinstance(value, dt.datetime), f"{label} is not a datetime")
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def isoformat(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def source_hashes(root: pathlib.Path) -> dict[str, str]:
    """Return named supplemental hashes; canonical coverage is proof_source_tree_sha256."""

    return {name: sha256_file(root / rel) for name, rel in SOURCE_INPUTS.items()}


def validate_source_policy(root: pathlib.Path) -> dict[str, Any]:
    swift_runner = root / "bindings" / "apple-device" / "Sources" / "QPeriaptDeviceRunner"
    offending_imports: list[str] = []
    for source in sorted(swift_runner.glob("*.swift")):
        for line_no, line in enumerate(read_text(source).splitlines(), start=1):
            if line.strip() == "import AppIntents":
                offending_imports.append(f"{source.relative_to(root)}:{line_no}")
    require(not offending_imports, f"Apple device runner must not import AppIntents: {offending_imports}")

    project = read_text(root / "bindings" / "apple-device" / "project.yml")
    require("AppIntents.framework" in project, "project.yml lacks AppIntents.framework Xcode 27 metadata dependency")
    require("weak: true" in project, "project.yml AppIntents.framework dependency must remain weak")
    return {
        "runner_imports_appintents": False,
        "appintents_dependency_declared_weak": True,
    }


def verify_source_hashes(root: pathlib.Path, proof: dict[str, Any]) -> None:
    expected = proof.get("source_inputs_sha256")
    require(isinstance(expected, dict), "proof lacks source_inputs_sha256")
    strict_keys(expected, set(SOURCE_INPUTS), "Apple device source-input hashes")
    for name, digest in expected.items():
        require(
            isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
            f"Apple device source-input hash is malformed: {name}",
        )
    current = source_hashes(root)
    for name, got in current.items():
        require(expected.get(name) == got, f"source input changed since device proof: {name}")


def validate_profile(
    profile: dict[str, Any],
    entitlements: dict[str, Any],
    bundle_id: str,
    device_id: str,
    expected_team: str,
    min_valid_days: int,
) -> dict[str, Any]:
    profile_name = profile.get("Name")
    team_ids = profile.get("TeamIdentifier")
    require(isinstance(profile_name, str) and profile_name, "embedded provisioning profile lacks Name")
    require(isinstance(team_ids, list) and all(isinstance(v, str) for v in team_ids), "profile lacks TeamIdentifier")

    code_team = entitlements.get("com.apple.developer.team-identifier")
    code_app_id = entitlements.get("application-identifier")
    require(isinstance(code_team, str) and code_team, "codesign entitlements lack team identifier")
    require(isinstance(code_app_id, str) and code_app_id, "codesign entitlements lack application identifier")
    if expected_team:
        require(expected_team in team_ids, f"profile team {team_ids} does not include DEVELOPMENT_TEAM={expected_team}")
        require(code_team == expected_team, f"codesign team {code_team} does not match DEVELOPMENT_TEAM={expected_team}")
    require(code_team in team_ids, f"codesign team {code_team} is not in profile TeamIdentifier={team_ids}")
    require(code_app_id == f"{code_team}.{bundle_id}", f"codesign application identifier {code_app_id} does not bind {bundle_id}")

    profile_entitlements = profile.get("Entitlements")
    require(isinstance(profile_entitlements, dict), "profile lacks Entitlements")
    profile_app_id = profile_entitlements.get("application-identifier")
    require(isinstance(profile_app_id, str) and profile_app_id, "profile lacks application-identifier")
    permitted_ids = {f"{code_team}.{bundle_id}", f"{code_team}.*"}
    require(profile_app_id in permitted_ids, f"profile application id {profile_app_id} does not permit {bundle_id}")

    provisioned_devices = profile.get("ProvisionedDevices")
    require(
        isinstance(provisioned_devices, list) and all(isinstance(v, str) for v in provisioned_devices),
        "development profile lacks ProvisionedDevices",
    )
    require(device_id in provisioned_devices, f"selected device {device_id} is not in the embedded profile")

    expiration = normalize_datetime(profile.get("ExpirationDate"), "profile ExpirationDate")
    days_remaining = int((expiration - utc_now()).total_seconds() // 86400)
    require(days_remaining >= 0, "profile is already expired")
    require(days_remaining >= min_valid_days, f"profile expires too soon: {days_remaining} days remaining, minimum is {min_valid_days}")

    return {
        "name": profile_name,
        "team_identifiers": team_ids,
        "team_name": profile.get("TeamName"),
        "application_identifier": profile_app_id,
        "is_xcode_managed": bool(profile.get("IsXcodeManaged")),
        "expiration": isoformat(expiration),
        "days_remaining": days_remaining,
        "min_valid_days": min_valid_days,
        "selected_device_in_profile": True,
        "codesign_application_identifier": code_app_id,
        "codesign_team_identifier": code_team,
        "get_task_allow": bool(entitlements.get("get-task-allow")),
    }


def validate_linkage_text(text: str) -> dict[str, Any]:
    require("libq_periapt_ffi" not in text, "device runner dynamically links libq_periapt_ffi")
    appintents_lines = [line.strip() for line in text.splitlines() if "AppIntents.framework/AppIntents" in line]
    appintents_state = "absent"
    if appintents_lines:
        require(all("weak" in line for line in appintents_lines), "AppIntents.framework is linked strongly; expected weak link")
        appintents_state = "weak"
    return {
        "rust_ffi_static": True,
        "appintents": appintents_state,
        "appintents_lines": appintents_lines,
    }


def validate_linkage(path: pathlib.Path) -> dict[str, Any]:
    snapshot = snapshot_file(path, "Apple linkage report")
    return validate_linkage_text(snapshot_text(snapshot, "Apple linkage report"))


def artifact_hashes(paths: dict[str, pathlib.Path]) -> dict[str, str]:
    return {name: sha256_file(path) for name, path in paths.items()}


def load_device_metadata(device_id: str, expected_device_type: str) -> dict[str, Any]:
    try:
        raw = subprocess.check_output(
            ["xcrun", "devicectl", "device", "info", "details", "--device", device_id, "--json-output", "-"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot run xcrun devicectl device info details for {device_id}: {exc}") from exc
    try:
        data = parse_strict_json_bytes(raw.encode("utf-8"), label="devicectl output")
    except EvidenceIOError as exc:
        raise SystemExit(f"error: cannot parse devicectl JSON output: {exc}") from exc
    require(isinstance(data, dict), "devicectl JSON root is not an object")
    result = data.get("result", {})
    props = result.get("properties", {})
    hardware = props.get("hardware", {})
    state = props.get("state", {})
    connection = props.get("connection", {})
    udid = hardware.get("udid")
    require(udid == device_id, f"devicectl returned device {udid}, expected {device_id}")
    device_type = hardware.get("deviceType")
    require(hardware.get("platform") == "iOS", f"selected device {device_id} is not iOS")
    require(hardware.get("reality") == "physical", f"selected device {device_id} is not physical")
    require(device_type in ("iPad", "iPhone"), f"selected device type is unsupported: {device_type}")
    if expected_device_type:
        require(device_type == expected_device_type, f"selected device type {device_type} does not match expected {expected_device_type}")
    readiness = (
        f"boot={state.get('bootState')} "
        f"connection={connection.get('state')} "
        f"pairing={connection.get('pairingState')} "
        f"transport={connection.get('transportType')}"
    )
    require(state.get("bootState") == "booted", f"selected device {device_id} is not booted ({readiness})")
    require(connection.get("pairingState") == "paired", f"selected device {device_id} is not paired ({readiness})")
    require(
        connection.get("state") == "connected",
        f"selected device {device_id} is not connected ({readiness}); "
        "devicectl 'available (paired)' is not accepted as runnable device proof",
    )
    require(developer_mode_enabled(state), f"selected device {device_id} does not have Developer Mode enabled")
    software = props.get("software", {})
    return {
        "label": "",
        "type": device_type,
        "product_type": hardware.get("productType"),
        "marketing_name": hardware.get("marketingName"),
        "os_version": software.get("osVersionNumber", {}).get("stringValue"),
        "os_build": software.get("osBuildVersions", {}).get("buildVersion", {}).get("name"),
        "boot_state": state.get("bootState"),
        "connection_state": connection.get("state"),
        "pairing_state": connection.get("pairingState"),
        "developer_mode_enabled": True,
    }


def emit(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    runs_root = device_runs_root(root)
    build_log = pathlib.Path(args.build_log).resolve()
    launch_log = pathlib.Path(args.launch_log).resolve()
    device_result = pathlib.Path(args.device_result).resolve()
    profile_plist = pathlib.Path(args.profile_plist).resolve()
    entitlements_plist = pathlib.Path(args.entitlements_plist).resolve()
    linkage = pathlib.Path(args.linkage).resolve()
    output = pathlib.Path(args.output).resolve()
    app = pathlib.Path(args.app).resolve()
    staticlib = pathlib.Path(args.staticlib).resolve()
    min_profile_valid_days = validate_min_profile_valid_days(args.min_profile_valid_days)

    for label, path in {
        "build log": build_log,
        "launch log": launch_log,
        "device result": device_result,
        "profile plist": profile_plist,
        "entitlements plist": entitlements_plist,
        "linkage file": linkage,
        "proof output": output,
    }.items():
        require_under(path, runs_root, label)
    require_under(app, root / "target", "device app path")
    require_under(staticlib, root / "target", "device staticlib path")

    require_clean_build_log(build_log)
    require_marker(launch_log, "device launch log", args.run_id)
    require_marker(device_result, "device result marker", args.run_id)
    device_metadata = load_device_metadata(args.device_id, args.expected_device_type)
    device_metadata["label"] = args.device_label

    profile = validate_profile(
        load_plist(profile_plist),
        load_plist(entitlements_plist),
        args.bundle_id,
        args.device_id,
        args.expected_team,
        min_profile_valid_days,
    )
    linkage_info = validate_linkage(linkage)
    source_policy = validate_source_policy(root)
    source_inputs = source_hashes(root)
    source_tree_dirty_at_emit = source_tree_dirty(root)
    require_source_snapshot_unchanged(
        root,
        args.expected_git_commit,
        args.expected_source_tree_sha256,
        "Apple device proof was running",
    )

    proof = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "git_commit": args.expected_git_commit,
        "source_tree_dirty": source_tree_dirty_at_emit,
        "proof_source_tree_sha256": args.expected_source_tree_sha256,
        "run_id": args.run_id,
        "generated_at": isoformat(utc_now()),
        "bundle_id": args.bundle_id,
        "device_id": args.device_id,
        "device_id_sha256": hashlib.sha256(args.device_id.encode("utf-8")).hexdigest(),
        "device": device_metadata,
        "developer_dir": os.environ.get("DEVELOPER_DIR", ""),
        "xcode_version": run_line(["xcodebuild", "-version"]).splitlines(),
        "swift_version": run_line(["xcrun", "swift", "--version"]).splitlines()[0],
        "rustc_version": run_line(["rustc", "--version"]),
        "app": {
            "path": str(app),
            "executable_sha256": sha256_file(app / "QPeriaptDeviceRunner"),
            "staticlib_path": str(staticlib),
            "staticlib_sha256": sha256_file(staticlib),
        },
        "checks": {
            "build_log_warning_free": True,
            "launch_marker_exact": True,
            "device_result_marker_exact": True,
            "profile_valid": True,
            "source_inputs_bound": True,
            "canonical_source_tree_bound": True,
        },
        "source_policy": source_policy,
        "profile": profile,
        "linkage": linkage_info,
        "artifacts_sha256": artifact_hashes(
            {
                "build_log": build_log,
                "launch_log": launch_log,
                "device_result": device_result,
                "profile_plist": profile_plist,
                "codesign_entitlements": entitlements_plist,
                "otool_l": linkage,
            }
        ),
        "source_inputs_sha256": source_inputs,
    }
    require_source_snapshot_unchanged(
        root,
        args.expected_git_commit,
        args.expected_source_tree_sha256,
        "Apple device proof was being emitted",
    )
    output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"APPLE_DEVICE_PROOF_JSON={output}")


def verify_proof_snapshot(
    root: pathlib.Path,
    proof_snapshot: JsonObjectSnapshot,
    build_log: pathlib.Path,
    launch_log: pathlib.Path,
    device_result: pathlib.Path,
    max_age_seconds: int,
    expected_device_type: str = "",
    allow_dirty_proof: bool = False,
) -> dict[str, Any]:
    proof_path = proof_snapshot.file.path
    runs_root = device_runs_root(root)
    for label, path in {
        "proof": proof_path,
        "build log": build_log,
        "launch log": launch_log,
        "device result": device_result,
    }.items():
        require_under(path, runs_root, label)
    max_age_seconds = validate_max_age_seconds(max_age_seconds)
    require_release_policy(max_age_seconds, allow_dirty_proof)
    proof = proof_snapshot.value
    strict_keys(proof, APPLE_PROOF_FIELDS, "Apple device proof")
    verify_proof_schema(proof, "Apple device proof")
    require(proof.get("status") == "pass", "Apple device proof status is not pass")
    checks = proof.get("checks")
    require(isinstance(checks, dict), "Apple device proof lacks checks")
    strict_keys(
        checks,
        {
            "build_log_warning_free",
            "launch_marker_exact",
            "device_result_marker_exact",
            "profile_valid",
            "source_inputs_bound",
            "canonical_source_tree_bound",
        },
        "Apple device checks",
    )
    require(all(value is True for value in checks.values()), "Apple device checks are not all true")
    run_id = proof.get("run_id")
    require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None, "Apple device proof lacks a valid run_id")
    verify_git_provenance(root, proof, allow_dirty_proof, "Apple device proof")
    verify_source_tree_digest(root, proof, "Apple device proof")
    verify_device_id_digest(proof, "Apple device proof")
    generated_at = parse_generated_at(proof.get("generated_at"))
    age = int((utc_now() - generated_at).total_seconds())
    require(age >= 0, "Apple device proof timestamp is in the future")
    require(age <= max_age_seconds, f"Apple device proof is stale: {age}s old, max is {max_age_seconds}s")

    verify_source_hashes(root, proof)
    current_source_policy = validate_source_policy(root)
    require(proof.get("source_policy") == current_source_policy, "Apple device source policy changed since proof")

    build_snapshot = snapshot_file(build_log, "Xcode build log")
    launch_snapshot = snapshot_file(launch_log, "device launch log")
    result_snapshot = snapshot_file(device_result, "device result marker")
    build_text = snapshot_text(build_snapshot, "Xcode build log")
    launch_text = snapshot_text(launch_snapshot, "device launch log")
    result_text = snapshot_text(result_snapshot, "device result marker")
    require_marker_text(launch_text, launch_log, "device launch log", run_id)
    require_marker_text(result_text, device_result, "device result marker", run_id)
    require_clean_build_log_text(build_text, build_log)

    expected_artifacts = proof.get("artifacts_sha256")
    require(isinstance(expected_artifacts, dict), "proof lacks artifacts_sha256")
    strict_keys(
        expected_artifacts,
        {
            "build_log",
            "launch_log",
            "device_result",
            "profile_plist",
            "codesign_entitlements",
            "otool_l",
        },
        "Apple device artifact hashes",
    )
    for name, expected in expected_artifacts.items():
        require(
            isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
            f"Apple device artifact hash is malformed: {name}",
        )

    require(proof_path.name.endswith("-device-proof.json"), f"unexpected Apple device proof filename: {proof_path.name}")
    prefix = proof_path.name[: -len("-device-proof.json")]
    profile_plist = proof_path.parent / f"{prefix}-embedded-profile.plist"
    entitlements_plist = proof_path.parent / f"{prefix}-codesign-entitlements.plist"
    linkage_path = proof_path.parent / f"{prefix}-otool-l.txt"
    profile_snapshot = snapshot_file(profile_plist, "embedded provisioning profile")
    entitlements_snapshot = snapshot_file(entitlements_plist, "codesign entitlements")
    linkage_snapshot = snapshot_file(linkage_path, "Apple linkage report")
    current_artifacts = {
        "build_log": build_snapshot.sha256,
        "launch_log": launch_snapshot.sha256,
        "device_result": result_snapshot.sha256,
        "profile_plist": profile_snapshot.sha256,
        "codesign_entitlements": entitlements_snapshot.sha256,
        "otool_l": linkage_snapshot.sha256,
    }
    for name, got in current_artifacts.items():
        require(expected_artifacts.get(name) == got, f"artifact changed since Apple device proof: {name}")

    profile = proof.get("profile")
    require(isinstance(profile, dict), "proof lacks profile metadata")
    strict_keys(
        profile,
        {
            "application_identifier",
            "codesign_application_identifier",
            "codesign_team_identifier",
            "days_remaining",
            "expiration",
            "get_task_allow",
            "is_xcode_managed",
            "min_valid_days",
            "name",
            "selected_device_in_profile",
            "team_identifiers",
            "team_name",
        },
        "Apple device profile metadata",
    )
    require(profile.get("selected_device_in_profile") is True, "proof profile does not include selected device")
    days_remaining = profile.get("days_remaining")
    min_valid_days = profile.get("min_valid_days")
    require(isinstance(days_remaining, int) and isinstance(min_valid_days, int), "proof profile validity is malformed")
    require_release_policy(
        max_age_seconds,
        allow_dirty_proof,
        min_profile_valid_days=min_valid_days,
    )
    require(days_remaining >= min_valid_days, "proof profile validity is below its recorded threshold")
    current_profile = validate_profile(
        parse_plist_bytes(profile_snapshot.data, str(profile_plist)),
        parse_plist_bytes(entitlements_snapshot.data, str(entitlements_plist)),
        str(proof.get("bundle_id")),
        str(proof.get("device_id")),
        str(profile.get("codesign_team_identifier")),
        min_valid_days,
    )
    require(
        current_profile.get("codesign_application_identifier") == profile.get("codesign_application_identifier"),
        "codesign application identifier changed since proof",
    )

    device = proof.get("device")
    require(isinstance(device, dict), "proof lacks device metadata")
    strict_keys(
        device,
        {
            "boot_state",
            "connection_state",
            "developer_mode_enabled",
            "label",
            "marketing_name",
            "os_build",
            "os_version",
            "pairing_state",
            "product_type",
            "type",
        },
        "Apple device metadata",
    )
    require(device.get("type") in ("iPad", "iPhone"), "proof device type is not iPad/iPhone")
    if expected_device_type:
        require(device.get("type") == expected_device_type, f"proof device type {device.get('type')} does not match expected {expected_device_type}")
    require(device.get("boot_state") == "booted", "proof device was not booted")
    require(device.get("connection_state") == "connected", "proof device was not connected")
    require(device.get("pairing_state") == "paired", "proof device was not paired")
    require(device.get("developer_mode_enabled") is True, "proof device did not have Developer Mode enabled")

    linkage = proof.get("linkage")
    require(isinstance(linkage, dict), "proof lacks linkage metadata")
    strict_keys(
        linkage,
        {"rust_ffi_static", "appintents", "appintents_lines"},
        "Apple linkage metadata",
    )
    current_linkage = validate_linkage_text(
        snapshot_text(linkage_snapshot, "Apple linkage report")
    )
    require(current_linkage.get("rust_ffi_static") is True, "current linkage does not establish static Rust FFI linkage")
    require(current_linkage.get("appintents") in ("absent", "weak"), "current AppIntents linkage is not weak/absent")
    require(linkage.get("rust_ffi_static") is True, "proof does not establish static Rust FFI linkage")
    require(linkage.get("appintents") in ("absent", "weak"), "proof AppIntents linkage is not weak/absent")

    app_info = proof.get("app")
    require(isinstance(app_info, dict), "proof lacks app metadata")
    strict_keys(
        app_info,
        {"path", "executable_sha256", "staticlib_path", "staticlib_sha256"},
        "Apple app metadata",
    )
    app_path = pathlib.Path(os.path.abspath(str(app_info.get("path"))))
    staticlib_path = pathlib.Path(os.path.abspath(str(app_info.get("staticlib_path"))))
    require_under(app_path, root / "target", "proof app path")
    require_under(staticlib_path, root / "target", "proof staticlib path")
    executable_snapshot = snapshot_file(
        app_path / "QPeriaptDeviceRunner", "Apple device executable"
    )
    staticlib_snapshot = snapshot_file(staticlib_path, "Apple Rust static library")
    require(executable_snapshot.sha256 == app_info.get("executable_sha256"), "app executable changed since proof")
    require(staticlib_snapshot.sha256 == app_info.get("staticlib_sha256"), "static Rust FFI library changed since proof")
    return proof


def verify_proof(
    root: pathlib.Path,
    proof_path: pathlib.Path,
    build_log: pathlib.Path,
    launch_log: pathlib.Path,
    device_result: pathlib.Path,
    max_age_seconds: int,
    expected_device_type: str = "",
    allow_dirty_proof: bool = False,
) -> dict[str, Any]:
    """Standalone producer-time verification without results-manifest binding."""

    snapshot = load_apple_json_snapshot(proof_path, "Apple device proof")
    return verify_proof_snapshot(
        root,
        snapshot,
        build_log,
        launch_log,
        device_result,
        max_age_seconds,
        expected_device_type,
        allow_dirty_proof,
    )


def parse_generated_at(value: Any) -> dt.datetime:
    require(isinstance(value, str) and value, "proof lacks generated_at")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SystemExit(f"error: invalid proof generated_at: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def cli_proof_snapshot(
    root: pathlib.Path,
    proof_path: pathlib.Path,
    *,
    results_manifest: str,
    expected_manifest_sha256: str,
    binding: str,
    label: str,
) -> tuple[JsonObjectSnapshot, bool]:
    bound = bool(results_manifest or expected_manifest_sha256)
    require(
        bool(results_manifest) == bool(expected_manifest_sha256),
        "--results-manifest and --expected-results-manifest-sha256 must be provided together",
    )
    if not bound:
        return load_apple_json_snapshot(proof_path, label), False
    manifest_path = pathlib.Path(os.path.abspath(results_manifest))
    require(
        manifest_path == pathlib.Path(os.path.abspath(root / "artifact" / "results.json")),
        "bound verification requires repository artifact/results.json",
    )
    try:
        manifest = load_results_manifest_snapshot(
            manifest_path,
            expected_sha256=expected_manifest_sha256,
        )
        return (
            select_bound_json_snapshot(
                root,
                manifest,
                binding=binding,
                selected_path=proof_path,
                maximum=MAX_APPLE_PROOF_BYTES,
                label=label,
            ),
            True,
        )
    except ProofManifestError as exc:
        raise SystemExit(f"error: {exc}") from exc


def verify(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    proof_path = rooted_lexical_path(root, args.proof)
    snapshot, manifest_bound = cli_proof_snapshot(
        root,
        proof_path,
        results_manifest=args.results_manifest,
        expected_manifest_sha256=args.expected_results_manifest_sha256,
        binding="apple_device",
        label="Apple device proof",
    )
    verify_proof_snapshot(
        root,
        snapshot,
        rooted_lexical_path(root, args.build_log),
        rooted_lexical_path(root, args.launch_log),
        rooted_lexical_path(root, args.device_result),
        args.max_age_seconds,
        args.expected_device_type,
        args.allow_dirty_proof,
    )
    print("APPLE_DEVICE_PROOF_JSON_PASS")
    if manifest_bound:
        print(
            "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS "
            f"section=apple_device sha256={snapshot.file.sha256}"
        )


def inspect_device(args: argparse.Namespace) -> None:
    metadata = load_device_metadata(args.device_id, args.expected_device_type)
    print(json.dumps(metadata, sort_keys=True))


def freeze_source(args: argparse.Namespace) -> None:
    commit, digest = freeze_source_snapshot(pathlib.Path(args.root).resolve())
    print(f"{commit}:{digest}")


def rel_to(path: pathlib.Path, base: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        raise SystemExit(f"error: matrix artifact path must be under {base}: {path}") from None


def matrix_artifact_path(matrix_root: pathlib.Path, entry: dict[str, Any], field: str, label: str) -> pathlib.Path:
    value = entry.get(field)
    require(isinstance(value, str) and value, f"matrix entry {label} missing {field}")
    pure = pathlib.PurePosixPath(value)
    require(
        not pure.is_absolute()
        and ".." not in pure.parts
        and pure.as_posix() == value
        and "\\" not in value,
        f"matrix entry {label} {field} is not a canonical relative path: {value}",
    )
    path = pathlib.Path(os.path.abspath(matrix_root.joinpath(*pure.parts)))
    try:
        path.relative_to(pathlib.Path(os.path.abspath(matrix_root)))
    except ValueError:
        raise SystemExit(f"error: matrix entry {label} {field} escapes matrix root: {value}") from None
    return path


def parse_entry(value: str) -> tuple[str, str, pathlib.Path]:
    parts = value.split(":", 2)
    if len(parts) != 3:
        raise SystemExit(f"error: matrix entry must be label:prefix:dir, got: {value}")
    label, prefix, directory = parts
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", label) is not None, f"invalid matrix label: {label}")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", prefix) is not None, f"invalid matrix prefix: {prefix}")
    return label, prefix, pathlib.Path(directory).resolve()


def emit_matrix(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    output = pathlib.Path(args.output).resolve()
    matrix_root = pathlib.Path(args.matrix_root).resolve()
    runs_root = device_runs_root(root)
    require_under(matrix_root, runs_root, "matrix root")
    require_under(output, matrix_root, "matrix proof output")
    max_age_seconds = validate_max_age_seconds(args.max_age_seconds)
    frozen_commit, frozen_digest = freeze_source_snapshot(root)
    require(len(args.entry) == 2, "Apple release matrix requires exactly ipad and iphone entries")
    entries_by_label: dict[str, dict[str, Any]] = {}
    seen_device_hashes: set[str] = set()
    seen_run_ids: set[str] = set()
    seen_proof_paths: set[pathlib.Path] = set()
    child_dirty_states: set[bool] = set()
    for raw_entry in args.entry:
        label, prefix, directory = parse_entry(raw_entry)
        require(label in REQUIRED_MATRIX_LABEL_TO_TYPE, f"unsupported matrix label: {label}")
        require(label not in entries_by_label, f"duplicate matrix label: {label}")
        require(prefix == label, f"matrix prefix for {label} must equal its canonical label")
        proof_path = directory / f"{prefix}-device-proof.json"
        build_log = directory / f"{prefix}-build.log"
        launch_log = directory / f"{prefix}-device-launch.log"
        device_result = directory / f"{prefix}-device-result.txt"
        proof_snapshot = load_apple_json_snapshot(proof_path, f"{label} child proof")
        proof = verify_proof_snapshot(
            root,
            proof_snapshot,
            build_log,
            launch_log,
            device_result,
            max_age_seconds,
            expected_device_type=REQUIRED_MATRIX_LABEL_TO_TYPE[label],
            allow_dirty_proof=args.allow_dirty_proof,
        )
        device = proof["device"]
        device_type = device["type"]
        require(device_type == REQUIRED_MATRIX_LABEL_TO_TYPE[label], f"matrix label {label} has type {device_type}")
        require(device.get("label") == label, f"child proof label differs for {label}")
        require(proof.get("git_commit") == frozen_commit, f"child proof commit differs for {label}")
        require(
            proof.get("proof_source_tree_sha256") == frozen_digest,
            f"child proof source digest differs for {label}",
        )
        require(type(proof.get("source_tree_dirty")) is bool, f"child proof dirty state is invalid for {label}")
        child_dirty_states.add(proof["source_tree_dirty"])
        device_hash = proof.get("device_id_sha256")
        run_id = proof.get("run_id")
        require(isinstance(device_hash, str) and SHA256_RE.fullmatch(device_hash) is not None, f"invalid device hash for {label}")
        require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None, f"invalid run id for {label}")
        require(device_hash not in seen_device_hashes, "matrix entries must use distinct physical devices")
        require(run_id not in seen_run_ids, "matrix entries must use distinct run ids")
        require(proof_path.resolve() not in seen_proof_paths, "matrix entries must use distinct child proofs")
        seen_device_hashes.add(device_hash)
        seen_run_ids.add(run_id)
        seen_proof_paths.add(proof_path.resolve())
        entries_by_label[label] = {
            "label": label,
            "prefix": prefix,
            "device_type": device_type,
            "product_type": device.get("product_type"),
            "marketing_name": device.get("marketing_name"),
            "os_version": device.get("os_version"),
            "os_build": device.get("os_build"),
            "device_id_sha256": device_hash,
            "run_id": run_id,
            "proof": rel_to(proof_path, matrix_root),
            "build_log": rel_to(build_log, matrix_root),
            "launch_log": rel_to(launch_log, matrix_root),
            "device_result": rel_to(device_result, matrix_root),
            "proof_sha256": proof_snapshot.file.sha256,
        }
    require(
        set(entries_by_label) == set(REQUIRED_MATRIX_LABEL_TO_TYPE),
        "Apple release matrix requires exactly ipad and iphone labels",
    )
    entries = [entries_by_label[label] for label in REQUIRED_MATRIX_LABEL_TO_TYPE]
    source_inputs = source_hashes(root)
    source_tree_dirty_at_emit = source_tree_dirty(root)
    require(
        child_dirty_states == {source_tree_dirty_at_emit},
        "child proofs and matrix proof must have the same dirty-source state",
    )
    require_source_snapshot_unchanged(
        root,
        frozen_commit,
        frozen_digest,
        "Apple device matrix proof was being assembled",
    )
    proof = {
        "schema_version": MATRIX_SCHEMA_VERSION,
        "status": "pass",
        "git_commit": frozen_commit,
        "source_tree_dirty": source_tree_dirty_at_emit,
        "proof_source_tree_sha256": frozen_digest,
        "generated_at": isoformat(utc_now()),
        "required_device_types": list(REQUIRED_MATRIX_TYPES),
        "source_inputs_sha256": source_inputs,
        "devices": entries,
    }
    require_source_snapshot_unchanged(
        root,
        frozen_commit,
        frozen_digest,
        "Apple device matrix proof was being emitted",
    )
    output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"APPLE_DEVICE_MATRIX_PROOF_JSON={output}")


def verify_matrix_snapshot(
    root: pathlib.Path,
    matrix_snapshot: JsonObjectSnapshot,
    matrix_root: pathlib.Path,
    max_age_seconds: int,
    allow_dirty_proof: bool,
) -> None:
    matrix_proof = matrix_snapshot.file.path
    runs_root = device_runs_root(root)
    require_under(matrix_root, runs_root, "matrix root")
    require_under(matrix_proof, matrix_root, "matrix proof")
    max_age_seconds = validate_max_age_seconds(max_age_seconds)
    require_release_policy(max_age_seconds, allow_dirty_proof)
    proof = matrix_snapshot.value
    strict_keys(proof, MATRIX_PROOF_FIELDS, "Apple device matrix proof")
    verify_proof_schema(
        proof,
        "Apple device matrix proof",
        MATRIX_SCHEMA_VERSION,
    )
    require(proof.get("status") == "pass", "Apple device matrix proof status is not pass")
    verify_git_provenance(root, proof, allow_dirty_proof, "Apple device matrix proof")
    verify_source_tree_digest(root, proof, "Apple device matrix proof")
    generated_at = parse_generated_at(proof.get("generated_at"))
    age = int((utc_now() - generated_at).total_seconds())
    require(age >= 0, "Apple device matrix proof timestamp is in the future")
    require(age <= max_age_seconds, f"Apple device matrix proof is stale: {age}s old, max is {max_age_seconds}s")
    verify_source_hashes(root, proof)
    required_types = proof.get("required_device_types")
    require(
        required_types == list(REQUIRED_MATRIX_TYPES),
        "matrix must require exactly iPad and iPhone in canonical order",
    )
    devices = proof.get("devices")
    require(isinstance(devices, list) and len(devices) == 2, "matrix proof must contain exactly two devices")
    seen_types: set[str] = set()
    seen_labels: set[str] = set()
    seen_device_hashes: set[str] = set()
    seen_run_ids: set[str] = set()
    seen_child_paths: set[pathlib.Path] = set()
    for entry in devices:
        require(isinstance(entry, dict), "matrix device entry is not an object")
        strict_keys(entry, MATRIX_ENTRY_FIELDS, "matrix device entry")
        label = entry.get("label")
        require(label in REQUIRED_MATRIX_LABEL_TO_TYPE, f"invalid matrix label: {label}")
        require(label not in seen_labels, f"duplicate matrix label: {label}")
        seen_labels.add(label)
        device_type = entry.get("device_type")
        require(
            device_type == REQUIRED_MATRIX_LABEL_TO_TYPE[label],
            f"matrix label {label} requires {REQUIRED_MATRIX_LABEL_TO_TYPE[label]}, got {device_type}",
        )
        seen_types.add(device_type)
        require(entry.get("prefix") == label, f"matrix prefix for {label} must equal its label")
        proof_path = matrix_artifact_path(matrix_root, entry, "proof", label)
        build_log = matrix_artifact_path(matrix_root, entry, "build_log", label)
        launch_log = matrix_artifact_path(matrix_root, entry, "launch_log", label)
        device_result = matrix_artifact_path(matrix_root, entry, "device_result", label)
        proof_sha256 = entry.get("proof_sha256")
        require(isinstance(proof_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", proof_sha256), f"matrix proof hash is malformed for {label}")
        child_snapshot = load_apple_json_snapshot(proof_path, f"{label} child proof")
        require(child_snapshot.file.sha256 == proof_sha256, f"matrix proof hash changed for {label}")
        child = verify_proof_snapshot(
            root,
            child_snapshot,
            build_log,
            launch_log,
            device_result,
            max_age_seconds,
            expected_device_type=device_type,
            allow_dirty_proof=allow_dirty_proof,
        )
        child_device = child.get("device")
        require(isinstance(child_device, dict), f"child proof lacks device metadata for {label}")
        require(child_device.get("label") == label, f"matrix child label changed for {label}")
        for entry_key, child_value in (
            ("device_type", child_device.get("type")),
            ("product_type", child_device.get("product_type")),
            ("marketing_name", child_device.get("marketing_name")),
            ("os_version", child_device.get("os_version")),
            ("os_build", child_device.get("os_build")),
            ("device_id_sha256", child.get("device_id_sha256")),
            ("run_id", child.get("run_id")),
        ):
            require(entry.get(entry_key) == child_value, f"matrix {entry_key} changed for {label}")
        require(child.get("git_commit") == proof.get("git_commit"), f"matrix child commit changed for {label}")
        require(
            child.get("proof_source_tree_sha256") == proof.get("proof_source_tree_sha256"),
            f"matrix child source digest changed for {label}",
        )
        require(
            child.get("source_tree_dirty") == proof.get("source_tree_dirty"),
            f"matrix child dirty state changed for {label}",
        )
        device_hash = entry.get("device_id_sha256")
        run_id = entry.get("run_id")
        require(device_hash not in seen_device_hashes, "matrix entries must use distinct physical devices")
        require(run_id not in seen_run_ids, "matrix entries must use distinct run ids")
        require(proof_path not in seen_child_paths, "matrix entries must use distinct child proofs")
        seen_device_hashes.add(device_hash)
        seen_run_ids.add(run_id)
        seen_child_paths.add(proof_path)
    require(seen_labels == set(REQUIRED_MATRIX_LABEL_TO_TYPE), "matrix must contain ipad and iphone labels")
    require(seen_types == set(REQUIRED_MATRIX_TYPES), "matrix must contain iPad and iPhone device types")


def verify_matrix(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    matrix_proof = rooted_lexical_path(root, args.matrix_proof)
    matrix_root = pathlib.Path(args.matrix_root).resolve() if args.matrix_root else matrix_proof.parent
    snapshot, manifest_bound = cli_proof_snapshot(
        root,
        matrix_proof,
        results_manifest=args.results_manifest,
        expected_manifest_sha256=args.expected_results_manifest_sha256,
        binding="apple_matrix",
        label="Apple device matrix proof",
    )
    verify_matrix_snapshot(
        root,
        snapshot,
        matrix_root,
        args.max_age_seconds,
        args.allow_dirty_proof,
    )
    print("APPLE_DEVICE_MATRIX_PROOF_JSON_PASS")
    if manifest_bound:
        print(
            "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS "
            f"section=apple_matrix sha256={snapshot.file.sha256}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    emit_parser = sub.add_parser("emit")
    emit_parser.add_argument("--root", required=True)
    emit_parser.add_argument("--app", required=True)
    emit_parser.add_argument("--bundle-id", required=True)
    emit_parser.add_argument("--device-id", required=True)
    emit_parser.add_argument("--run-id", required=True)
    emit_parser.add_argument("--device-label", default="")
    emit_parser.add_argument("--expected-device-type", choices=["", "iPad", "iPhone"], default="")
    emit_parser.add_argument("--expected-team", default="")
    emit_parser.add_argument("--min-profile-valid-days", type=int, default=30)
    emit_parser.add_argument("--staticlib", required=True)
    emit_parser.add_argument("--build-log", required=True)
    emit_parser.add_argument("--launch-log", required=True)
    emit_parser.add_argument("--device-result", required=True)
    emit_parser.add_argument("--profile-plist", required=True)
    emit_parser.add_argument("--entitlements-plist", required=True)
    emit_parser.add_argument("--linkage", required=True)
    emit_parser.add_argument("--output", required=True)
    emit_parser.add_argument("--expected-git-commit", required=True)
    emit_parser.add_argument("--expected-source-tree-sha256", required=True)
    emit_parser.set_defaults(func=emit)

    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--root", required=True)
    verify_parser.add_argument("--proof", required=True)
    verify_parser.add_argument("--build-log", required=True)
    verify_parser.add_argument("--launch-log", required=True)
    verify_parser.add_argument("--device-result", required=True)
    verify_parser.add_argument("--max-age-seconds", type=int, default=86400)
    verify_parser.add_argument("--expected-device-type", choices=["", "iPad", "iPhone"], default="")
    verify_parser.add_argument("--allow-dirty-proof", action="store_true")
    verify_parser.add_argument("--results-manifest", default="")
    verify_parser.add_argument("--expected-results-manifest-sha256", default="")
    verify_parser.set_defaults(func=verify)

    inspect_device_parser = sub.add_parser("inspect-device")
    inspect_device_parser.add_argument("--device-id", required=True)
    inspect_device_parser.add_argument("--expected-device-type", choices=["", "iPad", "iPhone"], default="")
    inspect_device_parser.set_defaults(func=inspect_device)

    freeze_source_parser = sub.add_parser("freeze-source")
    freeze_source_parser.add_argument("--root", required=True)
    freeze_source_parser.set_defaults(func=freeze_source)

    emit_matrix_parser = sub.add_parser("emit-matrix")
    emit_matrix_parser.add_argument("--root", required=True)
    emit_matrix_parser.add_argument("--matrix-root", required=True)
    emit_matrix_parser.add_argument("--output", required=True)
    emit_matrix_parser.add_argument("--entry", action="append", required=True)
    emit_matrix_parser.add_argument("--max-age-seconds", type=int, default=86400)
    emit_matrix_parser.add_argument("--allow-dirty-proof", action="store_true")
    emit_matrix_parser.set_defaults(func=emit_matrix)

    verify_matrix_parser = sub.add_parser("verify-matrix")
    verify_matrix_parser.add_argument("--root", required=True)
    verify_matrix_parser.add_argument("--matrix-proof", required=True)
    verify_matrix_parser.add_argument("--matrix-root", default="")
    verify_matrix_parser.add_argument("--max-age-seconds", type=int, default=86400)
    verify_matrix_parser.add_argument("--allow-dirty-proof", action="store_true")
    verify_matrix_parser.add_argument("--results-manifest", default="")
    verify_matrix_parser.add_argument("--expected-results-manifest-sha256", default="")
    verify_matrix_parser.set_defaults(func=verify_matrix)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
