#!/usr/bin/env python3
"""Emit and verify Q-Periapt physical Apple-device proof metadata."""

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
import sys
from typing import Any


SCHEMA_VERSION = 1
PASS_MARKER = "QPERIAPT_DEVICE_PASS"
FAIL_MARKER = "QPERIAPT_DEVICE_FAIL"
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_DEVICE_PROOF_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_PROFILE_VALID_DAYS = 366

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

SOURCE_TREES = {
    "rust_workspace_build_inputs": (
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "crates",
    ),
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


def load_plist(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
    except Exception as exc:  # plistlib raises several parse-specific exceptions.
        raise SystemExit(f"error: cannot parse plist {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"error: plist root is not a dictionary: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


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


def marker_count(path: pathlib.Path, run_id: str) -> int:
    marker = expected_marker(run_id)
    return sum(1 for line in read_text(path).splitlines() if line.strip() == marker)


def require_marker(path: pathlib.Path, label: str, run_id: str) -> None:
    text = read_text(path)
    require(FAIL_MARKER not in text, f"{label} contains {FAIL_MARKER}: {path}")
    count = marker_count(path, run_id)
    require(count == 1, f"{label} must contain exactly one {expected_marker(run_id)}, found {count}: {path}")
    legacy_count = sum(1 for line in text.splitlines() if line.strip() == PASS_MARKER)
    require(legacy_count == 0, f"{label} contains legacy bare {PASS_MARKER}: {path}")


def require_clean_build_log(path: pathlib.Path) -> None:
    for line_no, line in enumerate(read_text(path).splitlines(), start=1):
        if re.search(r"(^|[^A-Za-z])(warning|error):", line, flags=re.IGNORECASE):
            raise SystemExit(f"error: Xcode build log is not clean at {path}:{line_no}: {line}")


def run_line(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot run {' '.join(args)}: {exc}") from exc


def git_commit(root: pathlib.Path) -> str:
    commit = run_line(["git", "-C", str(root), "rev-parse", "HEAD"])
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, f"git commit hash is malformed: {commit}")
    return commit


def source_tree_dirty(root: pathlib.Path) -> bool:
    try:
        status = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot inspect git worktree status: {exc}") from exc
    return bool(status.strip())


def git_provenance(root: pathlib.Path) -> dict[str, Any]:
    return {
        "git_commit": git_commit(root),
        "source_tree_dirty": source_tree_dirty(root),
    }


def verify_git_provenance(root: pathlib.Path, proof: dict[str, Any], allow_dirty_proof: bool, label: str) -> None:
    commit = proof.get("git_commit")
    dirty = proof.get("source_tree_dirty")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, f"{label} lacks git_commit")
    require(isinstance(dirty, bool), f"{label} lacks source_tree_dirty")
    current_commit = git_commit(root)
    require(commit == current_commit, f"{label} was generated for git commit {commit}, current commit is {current_commit}")
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
    out: dict[str, str] = {}
    for name, rel in SOURCE_INPUTS.items():
        out[name] = sha256_file(root / rel)
    for name, rels in SOURCE_TREES.items():
        out[name] = tree_hash(root, rels)
    return out


def tree_hash(root: pathlib.Path, rels: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    seen = False
    for rel in rels:
        path = root / rel
        if path.is_file():
            candidates = [path]
        elif path.is_dir():
            candidates = sorted(p for p in path.rglob("*") if p.is_file())
        else:
            raise SystemExit(f"error: source input missing: {path}")
        for candidate in candidates:
            seen = True
            rel_name = candidate.resolve().relative_to(root.resolve()).as_posix()
            hasher.update(rel_name.encode("utf-8"))
            hasher.update(b"\0")
            hasher.update(hashlib.sha256(read_bytes(candidate)).digest())
            hasher.update(b"\0")
    require(seen, "source tree hash had no inputs")
    return hasher.hexdigest()


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


def validate_linkage(path: pathlib.Path) -> dict[str, Any]:
    text = read_text(path)
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
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: cannot parse devicectl JSON output: {exc}") from exc
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

    proof = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        **git_provenance(root),
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
        "source_inputs_sha256": source_hashes(root),
    }
    output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"APPLE_DEVICE_PROOF_JSON={output}")


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
    runs_root = device_runs_root(root)
    for label, path in {
        "proof": proof_path,
        "build log": build_log,
        "launch log": launch_log,
        "device result": device_result,
    }.items():
        require_under(path, runs_root, label)
    max_age_seconds = validate_max_age_seconds(max_age_seconds)
    proof = json.loads(read_text(proof_path))
    require(proof.get("schema_version") == SCHEMA_VERSION, "unsupported Apple device proof schema")
    require(proof.get("status") == "pass", "Apple device proof status is not pass")
    run_id = proof.get("run_id")
    require(isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None, "Apple device proof lacks a valid run_id")
    verify_git_provenance(root, proof, allow_dirty_proof, "Apple device proof")
    generated_at = parse_generated_at(proof.get("generated_at"))
    age = int((utc_now() - generated_at).total_seconds())
    require(age >= 0, "Apple device proof timestamp is in the future")
    require(age <= max_age_seconds, f"Apple device proof is stale: {age}s old, max is {max_age_seconds}s")

    verify_source_hashes(root, proof)
    current_source_policy = validate_source_policy(root)
    require(proof.get("source_policy") == current_source_policy, "Apple device source policy changed since proof")
    require_marker(launch_log, "device launch log", run_id)
    require_marker(device_result, "device result marker", run_id)
    require_clean_build_log(build_log)

    expected_artifacts = proof.get("artifacts_sha256")
    require(isinstance(expected_artifacts, dict), "proof lacks artifacts_sha256")
    current_artifacts = artifact_hashes(
        {
            "build_log": build_log,
            "launch_log": launch_log,
            "device_result": device_result,
        }
    )
    for name, got in current_artifacts.items():
        require(expected_artifacts.get(name) == got, f"artifact changed since Apple device proof: {name}")

    require(proof_path.name.endswith("-device-proof.json"), f"unexpected Apple device proof filename: {proof_path.name}")
    prefix = proof_path.name[: -len("-device-proof.json")]
    profile_plist = proof_path.parent / f"{prefix}-embedded-profile.plist"
    entitlements_plist = proof_path.parent / f"{prefix}-codesign-entitlements.plist"
    linkage_path = proof_path.parent / f"{prefix}-otool-l.txt"
    extra_artifacts = artifact_hashes(
        {
            "profile_plist": profile_plist,
            "codesign_entitlements": entitlements_plist,
            "otool_l": linkage_path,
        }
    )
    for name, got in extra_artifacts.items():
        require(expected_artifacts.get(name) == got, f"artifact changed since Apple device proof: {name}")

    profile = proof.get("profile")
    require(isinstance(profile, dict), "proof lacks profile metadata")
    require(profile.get("selected_device_in_profile") is True, "proof profile does not include selected device")
    days_remaining = profile.get("days_remaining")
    min_valid_days = profile.get("min_valid_days")
    require(isinstance(days_remaining, int) and isinstance(min_valid_days, int), "proof profile validity is malformed")
    require(days_remaining >= min_valid_days, "proof profile validity is below its recorded threshold")
    current_profile = validate_profile(
        load_plist(profile_plist),
        load_plist(entitlements_plist),
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
    require(device.get("type") in ("iPad", "iPhone"), "proof device type is not iPad/iPhone")
    if expected_device_type:
        require(device.get("type") == expected_device_type, f"proof device type {device.get('type')} does not match expected {expected_device_type}")
    require(device.get("boot_state") == "booted", "proof device was not booted")
    require(device.get("connection_state") == "connected", "proof device was not connected")
    require(device.get("pairing_state") == "paired", "proof device was not paired")
    require(device.get("developer_mode_enabled") is True, "proof device did not have Developer Mode enabled")

    linkage = proof.get("linkage")
    require(isinstance(linkage, dict), "proof lacks linkage metadata")
    current_linkage = validate_linkage(linkage_path)
    require(current_linkage.get("rust_ffi_static") is True, "current linkage does not establish static Rust FFI linkage")
    require(current_linkage.get("appintents") in ("absent", "weak"), "current AppIntents linkage is not weak/absent")
    require(linkage.get("rust_ffi_static") is True, "proof does not establish static Rust FFI linkage")
    require(linkage.get("appintents") in ("absent", "weak"), "proof AppIntents linkage is not weak/absent")

    app_info = proof.get("app")
    require(isinstance(app_info, dict), "proof lacks app metadata")
    app_path = pathlib.Path(str(app_info.get("path"))).resolve()
    staticlib_path = pathlib.Path(str(app_info.get("staticlib_path"))).resolve()
    require_under(app_path, root / "target", "proof app path")
    require_under(staticlib_path, root / "target", "proof staticlib path")
    require(sha256_file(app_path / "QPeriaptDeviceRunner") == app_info.get("executable_sha256"), "app executable changed since proof")
    require(sha256_file(staticlib_path) == app_info.get("staticlib_sha256"), "static Rust FFI library changed since proof")
    return proof


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


def verify(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    verify_proof(
        root,
        pathlib.Path(args.proof).resolve(),
        pathlib.Path(args.build_log).resolve(),
        pathlib.Path(args.launch_log).resolve(),
        pathlib.Path(args.device_result).resolve(),
        args.max_age_seconds,
        args.expected_device_type,
        args.allow_dirty_proof,
    )
    print("APPLE_DEVICE_PROOF_JSON_PASS")


def inspect_device(args: argparse.Namespace) -> None:
    metadata = load_device_metadata(args.device_id, args.expected_device_type)
    print(json.dumps(metadata, sort_keys=True))


def rel_to(path: pathlib.Path, base: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        raise SystemExit(f"error: matrix artifact path must be under {base}: {path}") from None


def matrix_artifact_path(matrix_root: pathlib.Path, entry: dict[str, Any], field: str, label: str) -> pathlib.Path:
    value = entry.get(field)
    require(isinstance(value, str) and value, f"matrix entry {label} missing {field}")
    path = (matrix_root / value).resolve()
    try:
        path.relative_to(matrix_root.resolve())
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
    required_types = [item for item in args.required_device_types.split(",") if item]
    require(required_types, "matrix requires at least one device type")
    require(set(required_types) <= {"iPad", "iPhone"}, f"unsupported required device types: {required_types}")
    entries = []
    seen_labels: set[str] = set()
    seen_types: set[str] = set()
    for raw_entry in args.entry:
        label, prefix, directory = parse_entry(raw_entry)
        require(label not in seen_labels, f"duplicate matrix label: {label}")
        seen_labels.add(label)
        proof_path = directory / f"{prefix}-device-proof.json"
        build_log = directory / f"{prefix}-build.log"
        launch_log = directory / f"{prefix}-device-launch.log"
        device_result = directory / f"{prefix}-device-result.txt"
        proof = verify_proof(root, proof_path, build_log, launch_log, device_result, max_age_seconds, allow_dirty_proof=args.allow_dirty_proof)
        device = proof["device"]
        device_type = device["type"]
        seen_types.add(device_type)
        entries.append(
            {
                "label": label,
                "prefix": prefix,
                "device_type": device_type,
                "product_type": device.get("product_type"),
                "marketing_name": device.get("marketing_name"),
                "os_version": device.get("os_version"),
                "os_build": device.get("os_build"),
                "device_id_sha256": proof.get("device_id_sha256"),
                "run_id": proof.get("run_id"),
                "proof": rel_to(proof_path, matrix_root),
                "build_log": rel_to(build_log, matrix_root),
                "launch_log": rel_to(launch_log, matrix_root),
                "device_result": rel_to(device_result, matrix_root),
                "proof_sha256": sha256_file(proof_path),
            }
        )
    require(set(required_types) <= seen_types, f"matrix missing required device types: {sorted(set(required_types) - seen_types)}")
    proof = {
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        **git_provenance(root),
        "generated_at": isoformat(utc_now()),
        "required_device_types": required_types,
        "source_inputs_sha256": source_hashes(root),
        "devices": entries,
    }
    output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"APPLE_DEVICE_MATRIX_PROOF_JSON={output}")


def verify_matrix(args: argparse.Namespace) -> None:
    root = pathlib.Path(args.root).resolve()
    matrix_proof = pathlib.Path(args.matrix_proof).resolve()
    matrix_root = pathlib.Path(args.matrix_root).resolve() if args.matrix_root else matrix_proof.parent
    runs_root = device_runs_root(root)
    require_under(matrix_root, runs_root, "matrix root")
    require_under(matrix_proof, matrix_root, "matrix proof")
    max_age_seconds = validate_max_age_seconds(args.max_age_seconds)
    proof = json.loads(read_text(matrix_proof))
    require(proof.get("schema_version") == SCHEMA_VERSION, "unsupported Apple device matrix proof schema")
    require(proof.get("status") == "pass", "Apple device matrix proof status is not pass")
    verify_git_provenance(root, proof, args.allow_dirty_proof, "Apple device matrix proof")
    generated_at = parse_generated_at(proof.get("generated_at"))
    age = int((utc_now() - generated_at).total_seconds())
    require(age >= 0, "Apple device matrix proof timestamp is in the future")
    require(age <= max_age_seconds, f"Apple device matrix proof is stale: {age}s old, max is {max_age_seconds}s")
    verify_source_hashes(root, proof)
    required_types = proof.get("required_device_types")
    require(isinstance(required_types, list) and set(required_types) <= {"iPad", "iPhone"}, "matrix required device types malformed")
    devices = proof.get("devices")
    require(isinstance(devices, list) and devices, "matrix proof has no devices")
    seen_types: set[str] = set()
    seen_labels: set[str] = set()
    for entry in devices:
        require(isinstance(entry, dict), "matrix device entry is not an object")
        label = entry.get("label")
        require(isinstance(label, str) and label not in seen_labels, f"duplicate or invalid matrix label: {label}")
        seen_labels.add(label)
        device_type = entry.get("device_type")
        require(device_type in ("iPad", "iPhone"), f"matrix entry has invalid device type: {device_type}")
        seen_types.add(device_type)
        proof_path = matrix_artifact_path(matrix_root, entry, "proof", label)
        build_log = matrix_artifact_path(matrix_root, entry, "build_log", label)
        launch_log = matrix_artifact_path(matrix_root, entry, "launch_log", label)
        device_result = matrix_artifact_path(matrix_root, entry, "device_result", label)
        proof_sha256 = entry.get("proof_sha256")
        require(isinstance(proof_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", proof_sha256), f"matrix proof hash is malformed for {label}")
        require(sha256_file(proof_path) == proof_sha256, f"matrix proof hash changed for {label}")
        child = verify_proof(root, proof_path, build_log, launch_log, device_result, max_age_seconds, allow_dirty_proof=args.allow_dirty_proof)
        require(child.get("device", {}).get("type") == device_type, f"matrix device type changed for {label}")
    require(set(required_types) <= seen_types, f"matrix missing required device types: {sorted(set(required_types) - seen_types)}")
    print("APPLE_DEVICE_MATRIX_PROOF_JSON_PASS")


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
    verify_parser.set_defaults(func=verify)

    inspect_device_parser = sub.add_parser("inspect-device")
    inspect_device_parser.add_argument("--device-id", required=True)
    inspect_device_parser.add_argument("--expected-device-type", choices=["", "iPad", "iPhone"], default="")
    inspect_device_parser.set_defaults(func=inspect_device)

    emit_matrix_parser = sub.add_parser("emit-matrix")
    emit_matrix_parser.add_argument("--root", required=True)
    emit_matrix_parser.add_argument("--matrix-root", required=True)
    emit_matrix_parser.add_argument("--output", required=True)
    emit_matrix_parser.add_argument("--required-device-types", default="iPad,iPhone")
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
    verify_matrix_parser.set_defaults(func=verify_matrix)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
