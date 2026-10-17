"""Explicit build-profile partitions and complete installed-consumer coverage."""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

PROFILES = ("debug", "release")
CONSUMERS = {
    "swift": ("Swift", "swift_consumer"),
    "kotlin": ("Kotlin", "kotlin_consumer"),
    "android": ("AndroidJNI", "android_jni_consumer"),
}


def validate_profiles(profiles: tuple[str, ...]) -> tuple[str, ...]:
    sdk.require(type(profiles) is tuple and profiles in (PROFILES, ("debug",), ("release",)),
                "build profiles must be debug, release, or both in canonical order")
    return profiles


def require_execution(result: dict, profiles: tuple[str, ...], key: str) -> None:
    validate_profiles(profiles)
    sdk.require(result.get("build_profiles") == list(profiles)
                and isinstance(result.get(key), dict) and set(result[key]) == set(profiles)
                and all(isinstance(row, dict) and row for row in result[key].values()),
                "consumer execution differs from the requested build profiles")


def require_native(native: dict, profiles: tuple[str, ...]) -> None:
    sdk.require(native.get("partition_completed") is True
                and native.get("completed") is (profiles == PROFILES),
                "native profile qualification is incomplete or claims unexecuted profiles")
    require_execution(native, profiles, "execution")


def verify_partitions(directory: Path, *, source_commit: str, source_inputs: dict) -> dict:
    """Check six same-source receipts; do not reinterpret partial runs as packages.

    Each producer still runs its existing scenario validators before finishing.
    This join verifies their profile union and retains hashes of the complete
    reports, rather than flattening them or reusing binaries across runners.
    """
    sdk.require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
                "coverage requires an exact source commit")
    expected = {f"continuity-installed-{consumer}-{profile}"
                for consumer in CONSUMERS for profile in PROFILES}
    sdk.require(directory.is_dir() and not directory.is_symlink()
                and {p.name for p in directory.iterdir()} == expected,
                "installed consumer partition set is missing, duplicated, or unexpected")
    receipts = {}
    sdk_report = None
    compiler = None
    for consumer, (language, field) in CONSUMERS.items():
        for profile in PROFILES:
            name = f"continuity-installed-{consumer}-{profile}"
            folder = directory / name
            sdk.require(folder.is_dir() and not folder.is_symlink(), "partition must be a directory")
            pinned = sdk.snapshot(folder / "CONTINUITY_PACKAGE.json")
            row = parse_strict_json_bytes(pinned.data, label="installed consumer partition")
            sdk.require(isinstance(row, dict) and type(row.get("schema_version")) is int
                        and row["schema_version"] == 1
                        and row.get("kind") == "qperiapt.continuity_candidate_package_partition"
                        and row.get("completed") is False and row.get("partition_completed") is True
                        and row.get("sources_unchanged") is True and "failure" not in row
                        and row.get("release_claim_eligible") is False
                        and row.get("publication_performed") is False,
                        "partition is unfinished or makes a complete-package claim")
            sdk.require(row.get("source_commit") == source_commit and row.get("source_inputs") == source_inputs,
                        "partition source identity differs")
            sdk.require(row.get("host_os") == "Darwin" and row.get("host_arch") == "arm64",
                        "foreign partition host must be macOS arm64")
            sdk.require(row.get("requested_consumers") == ["Rust", "C", language]
                        and {key for _, key in CONSUMERS.values() if key in row} == {field},
                        "partition consumer identity differs")
            require_execution(row, (profile,), "execution")
            native = row.get("c_consumer")
            foreign = row.get(field)
            sdk.require(isinstance(native, dict) and isinstance(foreign, dict),
                        "partition omitted its native or foreign result")
            require_native(native, (profile,))
            require_execution(foreign, (profile,), "profiles")
            sdk.require(foreign.get("completed") is False and foreign.get("partition_completed") is True
                        and "failure" not in foreign
                        and "failure" not in native and native.get("release_claim_eligible") is False
                        and foreign.get("release_claim_eligible") is False,
                        "partition consumer did not finish its requested profile")
            if consumer == "swift":
                apple = row.get("apple_package")
                minimum = foreign.get("minimum_root")
                sdk.require(isinstance(apple, dict) and apple.get("completed") is True
                            and isinstance(minimum, dict) and minimum.get("completed") is True,
                            "Swift partition omitted Apple packaging or minimum-compiler execution")
            else:
                sdk.require("apple_package" not in row, "partition includes an unexpected Apple package")
            report = row.get("rust_report_sha256")
            rustc = row.get("rustc")
            sdk.require(isinstance(report, str) and re.fullmatch(r"[0-9a-f]{64}", report) is not None
                        and isinstance(rustc, str) and rustc.startswith("rustc 1.98.1 (48a229cea 2026-09-01)\n"),
                        "partition SDK report or compiler identity is missing")
            if sdk_report is None:
                sdk_report, compiler = report, rustc
            sdk.require((report, rustc) == (sdk_report, compiler),
                        "partitions consumed different SDK reports or compilers")
            receipts[name] = {"report_sha256": pinned.sha256, "report_bytes": pinned.size,
                              "consumer": language, "build_profile": profile}
    return {"schema_version": 1, "kind": "qperiapt.continuity_profile_coverage", "completed": True,
            "source_commit": source_commit, "rust_report_sha256": sdk_report,
            "build_profiles": list(PROFILES), "consumers": [v[0] for v in CONSUMERS.values()],
            "partitions": receipts, "release_claim_eligible": False, "publication_performed": False,
            "scope": "same-source debug/release partition receipt coverage for installed Rust/C and "
                     "Swift/Kotlin/Android JNI consumers; scenario evidence remains in each producer artifact; "
                     "not physical-device, independent-engine, or release qualification"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    import continuity_package as package
    commit, dirty = sdk.inspect_package_source(package.ROOT, allow_dirty=False)
    sdk.require(not dirty and commit == args.source_commit, "coverage checkout identity differs")
    before = package.source_inputs()
    result = verify_partitions(args.input, source_commit=commit, source_inputs=before)
    sdk.require(before == package.source_inputs()
                and sdk.inspect_package_source(package.ROOT, allow_dirty=False) == (commit, dirty),
                "coverage source changed during verification")
    sdk.require(not args.output.exists() and not args.output.is_symlink(), "coverage output already exists")
    sdk.write_json(args.output, result)
    print("CONTINUITY_PROFILE_COVERAGE_PASS commit=" + commit + " partitions=6 release_claim_eligible=false")


if __name__ == "__main__":
    main()
