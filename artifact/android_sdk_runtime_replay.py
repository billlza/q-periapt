#!/usr/bin/env python3
"""Transport both public SDK runtime closures and replay their exact SDK tools.

No Gradle, adb or emulator invocation. Source/AAR pins come from the caller;
archive extraction is owned by workflow_artifact's fixed profile contract.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat

from android_agp_consumer import verify_export_file_set, verify_exported_profile
from android_agp_consumer_contract import SDK_PROFILES, export_file_names, flat_sdk_export_files, require
from android_runtime_state import registered_sdk_root
from evidence_io import fresh_output_directory, load_json_object_snapshot, read_regular_snapshot
from workflow_artifact import ANDROID_SDK_RUNTIME_REPLAY_PROFILES

ROOT = Path(__file__).resolve().parent.parent


def _fresh(path: Path) -> Path:
    admitted = fresh_output_directory(path, within=ROOT / "target", label="SDK runtime replay output")
    admitted.mkdir(mode=0o700)
    return admitted


def _copy(source: Path, destination: Path, maximum: int) -> str:
    def public_file(metadata: os.stat_result) -> None:
        require(metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o644,
                "public SDK runtime evidence must be one mode-0644 regular file")

    snapshot = read_regular_snapshot(source, maximum=maximum, label="public SDK runtime evidence",
                                     validate_metadata=public_file)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(snapshot.data)
        stream.flush()
        os.fchmod(stream.fileno(), 0o644)
    return snapshot.sha256


def select_exports(runs: Path) -> dict[str, Path]:
    """The two successful profiles must be the entire producer run set."""
    require(runs.is_dir() and not runs.is_symlink(), "SDK runtime run root differs")
    entries = list(islice(runs.iterdir(), 3))
    require(len(entries) == 2, "SDK runtime staging requires exactly two runs, without ignored attempts")
    selected = {}
    for run in entries:
        require(not run.is_symlink() and run.is_dir()
                and re.fullmatch(r"[0-9a-f]{32}", run.name) is not None, "SDK runtime run directory differs")
        directory = run / "proof/agp-evidence"
        proof = load_json_object_snapshot(directory / "proof.json", maximum=1024**2,
                                          label="SDK runtime public proof").value
        consumer = proof.get("consumer")
        require(isinstance(consumer, dict), "SDK runtime consumer is missing")
        profile = consumer.get("profile")
        require(isinstance(profile, str) and profile in SDK_PROFILES and profile not in selected,
                "SDK runtime profiles are missing, duplicated or unsupported")
        require(proof.get("run_id") == run.name, "SDK runtime run ID differs")
        selected[profile] = directory
    require(set(selected) == SDK_PROFILES, "SDK runtime requires full and minimal profiles")
    return selected


def restore(flat: Path, output: Path, runtime_profile: str) -> dict[str, Path]:
    mapping = flat_sdk_export_files()
    require(flat.is_dir() and not flat.is_symlink(), "SDK runtime transport directory differs")
    entries = list(islice(flat.iterdir(), len(mapping) + 1))
    require({entry.name for entry in entries} == set(mapping), "SDK runtime transport file set differs")
    require(all(entry.is_file() and not entry.is_symlink() for entry in entries),
            "SDK runtime transport contains a non-regular file")
    spec = ANDROID_SDK_RUNTIME_REPLAY_PROFILES[runtime_profile]
    bounds = {member.destination_name: member.maximum_bytes for member in spec.containers[0].members}
    directories = {profile: output / profile for profile in sorted(SDK_PROFILES)}
    for leaf, (profile, relative) in mapping.items():
        _copy(flat / leaf, directories[profile] / relative, bounds[leaf])
    return directories


def run(command: str, *, runtime_profile: str, sdk: Path, source_commit: str,
        aar_sha256: str, manifest_sha256: str) -> dict:
    require(command in {"stage", "verify"}, "unknown SDK runtime replay operation")
    require(runtime_profile in ANDROID_SDK_RUNTIME_REPLAY_PROFILES, "unsupported SDK runtime replay target")
    require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None, "SDK source commit is malformed")
    for digest in (aar_sha256, manifest_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "SDK artifact digest is malformed")
    runs = ROOT / "target/qperiapt-android-device-smoke-runs"
    if command == "verify":
        require(not os.path.lexists(runs) and not os.path.lexists(ROOT / "target/qperiapt-android-aar"),
                "independent replay requires original run and AAR directories to be absent")
    output = _fresh(ROOT / f"target/android-sdk-runtime-{command}-{runtime_profile}")
    report = {"schema": 1, "kind": "qperiapt.android_sdk_runtime_replay", "operation": command,
              "runtime_profile": runtime_profile, "source_commit": source_commit,
              "aar_sha256": aar_sha256, "manifest_sha256": manifest_sha256,
              "started_utc": datetime.now(timezone.utc).isoformat(), "completed": False,
              "release_claim_eligible": False, "profiles": []}
    try:
        spec = ANDROID_SDK_RUNTIME_REPLAY_PROFILES[runtime_profile]
        if command == "stage":
            selected = select_exports(runs)
            for profile, directory in selected.items():
                verify_export_file_set(directory, export_file_names("emulator", profile))
            flat = _fresh(ROOT / f"target/android-sdk-runtime-export-{runtime_profile}")
            mapping = flat_sdk_export_files()
            report["transport_sha256"] = {}
            for member in spec.containers[0].members:
                profile, relative = mapping[member.archive_name]
                digest = _copy(selected[profile] / relative, flat / member.archive_name, member.maximum_bytes)
                report["transport_sha256"][member.archive_name] = digest
        else:
            flat = ROOT / spec.destination
        # Verify the exact bytes that will be transported, not the original run
        # paths. A failed producer stage cannot upload a successful closure.
        directories = restore(flat, output, runtime_profile)
        for profile, directory in directories.items():
            report["profiles"].append(verify_exported_profile(
                ROOT, directory, expected_profile=profile, expected_aar_sha256=aar_sha256,
                expected_aar_manifest_sha256=manifest_sha256, expected_source_commit=source_commit,
                sdk=sdk, expected_device_abi="x86_64", expected_runtime_profile=runtime_profile,
            ))
        report["completed"] = True
    except BaseException as error:
        report["failure"] = {"kind": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        with (output / "REPORT.json").open("x") as stream:
            stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "verify"))
    parser.add_argument("--runtime-profile", choices=tuple(ANDROID_SDK_RUNTIME_REPLAY_PROFILES), required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-aar-sha256", required=True)
    parser.add_argument("--expected-aar-manifest-sha256", required=True)
    args = parser.parse_args()
    report = run(args.command, runtime_profile=args.runtime_profile, sdk=registered_sdk_root(args.sdk),
                 source_commit=args.expected_source_commit, aar_sha256=args.expected_aar_sha256,
                 manifest_sha256=args.expected_aar_manifest_sha256)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
