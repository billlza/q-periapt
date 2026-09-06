"""Pure schema for exact-AAR AGP consumer projections, independent of release I/O."""

from __future__ import annotations

import re
from typing import Any


class AndroidAgpConsumerError(RuntimeError):
    """The selected AGP consumer evidence does not satisfy its fixed contract."""


AGP_VERSION = "9.4.0"
GRADLE_VERSION = "9.7.1"
PROOF_KIND = "qperiapt.android_agp_consumer_proof"
BUILD_KIND = "qperiapt.android_agp_consumer_build"
PROFILES = frozenset({"agp_full_release", "agp_minimal_release"})
PROJECTION_FIELDS = frozenset(
    {
        "profile",
        "proof_sha256",
        "run_id",
        "source_commit",
        "source_tree_sha256",
        "aar_sha256",
        "aar_manifest_sha256",
        "apk_sha256",
        "build_receipt_sha256",
        "result_json_sha256",
        "passed_tests",
        "agp_version",
        "gradle_version",
    }
)
SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
PROFILE_TESTS = {
    "agp_full_release": (
        "runtimeMetadataMatches",
        "signedPolicyDecisionIsExactAndFailClosed",
        "osRandomPolicyRoundtripAndWipes",
    ),
    "agp_minimal_release": ("runtimeVersionOnly",),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidAgpConsumerError(message)


def _object(
    value: object, fields: frozenset[str] | set[str], label: str
) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == fields, f"{label} fields differ")
    return value


def _hash(value: object, label: str) -> str:
    require(
        isinstance(value, str) and SHA256.fullmatch(value) is not None,
        f"invalid {label} SHA-256",
    )
    return value


def validate_profile_projection(
    value: object,
    *,
    expected_profile: str,
    expected_aar_sha256: str,
    expected_aar_manifest_sha256: str,
    expected_source_commit: str,
) -> dict[str, object]:
    """Validate the fixed public projection without filesystem, Gradle, or device access."""
    require(
        isinstance(expected_profile, str) and expected_profile in PROFILES,
        "unknown AGP consumer profile",
    )
    record = _object(value, PROJECTION_FIELDS, "AGP consumer projection")
    require(record["profile"] == expected_profile, "AGP projection profile mismatch")
    require(
        isinstance(record["run_id"], str)
        and RUN_ID.fullmatch(record["run_id"]) is not None,
        "invalid AGP run id",
    )
    require(
        isinstance(expected_source_commit, str)
        and COMMIT.fullmatch(expected_source_commit) is not None,
        "invalid expected AGP source commit",
    )
    require(
        record["source_commit"] == expected_source_commit, "AGP source commit mismatch"
    )
    for name in PROJECTION_FIELDS:
        if name.endswith("_sha256"):
            _hash(record[name], name)
    require(
        record["aar_sha256"] == _hash(expected_aar_sha256, "expected AAR"),
        "AGP AAR mismatch",
    )
    require(
        record["aar_manifest_sha256"]
        == _hash(expected_aar_manifest_sha256, "expected AAR manifest"),
        "AGP AAR manifest mismatch",
    )
    require(
        record["agp_version"] == AGP_VERSION
        and record["gradle_version"] == GRADLE_VERSION,
        "AGP consumer toolchain mismatch",
    )
    require(
        record["passed_tests"] == list(PROFILE_TESTS[expected_profile]),
        "AGP projection workload mismatch",
    )
    return dict(record)
