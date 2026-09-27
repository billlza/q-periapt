"""Pure schema for exact-AAR AGP consumer projections, independent of release I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from android_runtime_profile import DEFAULT_RUNTIME_PROFILE, runtime_profile


class AndroidAgpConsumerError(RuntimeError):
    """The selected AGP consumer evidence does not satisfy its fixed contract."""


AGP_VERSION = "9.4.0"
GRADLE_VERSION = "9.7.1"
PROOF_KIND = "qperiapt.android_agp_consumer_proof"
BUILD_KIND = "qperiapt.android_agp_consumer_build"
# The historical maintenance transaction imports PROFILES. Keep its admitted
# profiles and projection shape frozen; only the collector dispatch uses ALL.
PROFILES = frozenset({"agp_full_release", "agp_minimal_release"})
SDK_PROFILES = frozenset({"agp_sdk_full_release", "agp_sdk_minimal_release"})
ALL_PROFILES = PROFILES | SDK_PROFILES
SDK_PROOF_KIND = "qperiapt.android_sdk_agp_consumer_proof"
SDK_BUILD_KIND = "qperiapt.android_sdk_agp_consumer_build"
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
    "agp_sdk_full_release": (
        "sdkOwnersAndPurposeKeys",
        "sdkExpertCancellationAndInputSnapshot",
        "sdkSignedPolicyRevocationAndRecovery",
    ),
    "agp_sdk_minimal_release": ("runtimeVersionOnly",),
}


@dataclass(frozen=True)
class ProfileSpec:
    aar_profile: str
    version: str
    flavor: str
    smoke_directory: str
    workload: str | None
    fixtures: tuple[str, ...]

    @property
    def proof_kind(self) -> str:
        return SDK_PROOF_KIND if self.aar_profile == "sdk-alpha1" else PROOF_KIND

    @property
    def build_kind(self) -> str:
        return SDK_BUILD_KIND if self.aar_profile == "sdk-alpha1" else BUILD_KIND


PROFILE_SPECS = {
    "agp_full_release": ProfileSpec("legacy", "0.1.5", "Full", "full",
        "QPeriaptSmokeWorkload.java", ("signed-policy-vectors.json",)),
    "agp_minimal_release": ProfileSpec("legacy", "0.1.5", "Minimal", "minimal", None, ()),
    "agp_sdk_full_release": ProfileSpec("sdk-alpha1", "0.2.0-alpha.1", "Full", "sdk",
        "QPeriaptSDKWorkload.java", ("signed-policy-vectors.json",
            "sdk-policy-revocation-vectors.json", "sdk-policy-update-vectors.json")),
    "agp_sdk_minimal_release": ProfileSpec("sdk-alpha1", "0.2.0-alpha.1", "Minimal", "sdk-minimal", None, ()),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidAgpConsumerError(message)


def profile_spec(profile: str) -> ProfileSpec:
    require(isinstance(profile, str) and profile in ALL_PROFILES, "unknown AGP consumer profile")
    return PROFILE_SPECS[profile]


def runtime_target(
    profile: str, expected_device_abi: str | None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    """The caller selects both architecture and runtime; evidence cannot choose."""
    profile_spec(profile)
    if profile in SDK_PROFILES:
        require(isinstance(expected_device_abi, str) and expected_device_abi in {"arm64-v8a", "x86_64"},
                "SDK AGP verification requires an explicit arm64-v8a or x86_64 target")
        abi = expected_device_abi
    else:
        require(expected_runtime_profile == DEFAULT_RUNTIME_PROFILE,
                "legacy AGP target must remain API 35 / 16 KiB")
        require(expected_device_abi is None or expected_device_abi == "arm64-v8a", "legacy AGP target must remain arm64-v8a")
        abi = "arm64-v8a"
    try:
        return runtime_profile(expected_runtime_profile).target(abi)
    except ValueError as error:
        raise AndroidAgpConsumerError(str(error)) from error


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
    expected_device_abi: str | None = None,
    expected_runtime_profile: str = DEFAULT_RUNTIME_PROFILE,
) -> dict[str, object]:
    """Validate the fixed public projection without filesystem, Gradle, or device access."""
    require(
        isinstance(expected_profile, str) and expected_profile in ALL_PROFILES,
        "unknown AGP consumer profile",
    )
    target = runtime_target(expected_profile, expected_device_abi, expected_runtime_profile)
    sdk_profile = expected_profile in SDK_PROFILES
    record = _object(value, PROJECTION_FIELDS | ({"runtime_target"} if sdk_profile else set()), "AGP consumer projection")
    if sdk_profile:
        selected_target = _object(record["runtime_target"], set(target), "SDK AGP runtime target")
        require(type(selected_target["sdk"]) is int and type(selected_target["page_size"]) is int
                and selected_target == target, "SDK AGP runtime target mismatch")
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
