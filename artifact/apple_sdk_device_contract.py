"""Closed SDK device-capture identity, separate from historical Apple schemas."""
from __future__ import annotations

import re

LEGACY_PROFILE = "legacy"
SDK_PROFILE = "sdk-alpha1"
CAPTURE_PROFILES = (LEGACY_PROFILE, SDK_PROFILE)
SDK_VERSION = "0.2.0-alpha.1"
SDK_DEVICE_SCHEMA = 1
SDK_MATRIX_SCHEMA = 1
SDK_DEVICE_KIND = "qperiapt.apple_sdk_device_proof"
SDK_MATRIX_KIND = "qperiapt.apple_sdk_matrix_proof"
SDK_TESTS = (
    "compatibilitySignedPolicy",
    "ownedKeysAndPurposeDerivation",
    "expertTransferAndPolicyRevocation",
    "resourceLimitsAndCancellation",
)
SDK_SOURCE_INPUTS = {
    "apple_sdk_device_contract": "artifact/apple_sdk_device_contract.py",
    "apple_sdk_device_workload": "bindings/apple-device/Sources/QPeriaptDeviceRunner/SDKDeviceSmoke.swift",
    "swift_sdk_binding": "bindings/swift/Sources/QPeriaptSDK/QPeriaptSDK.swift",
    "sdk_revocation_vector": "bindings/sdk-policy-revocation-vectors.json",
    "sdk_update_vector": "bindings/sdk-policy-update-vectors.json",
    "sdk_abi_contract": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-alpha1.json",
    "swift_c_modulemap": "bindings/swift/Sources/CQPeriapt/module.modulemap",
}


def validate_capture_profile(profile: str) -> str:
    if profile not in CAPTURE_PROFILES:
        raise ValueError("unsupported Apple device capture profile")
    return profile


def sdk_metadata() -> dict:
    return {"profile": SDK_PROFILE, "package_version": SDK_VERSION, "abi_major": 2,
            "extension_revision": 1, "tests": list(SDK_TESTS),
            "policy_update_storage": "test-only in-memory state"}


def sdk_marker(run_id: str) -> str:
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{32}", run_id) is None:
        raise ValueError("invalid Apple SDK device run id")
    return (f"QPERIAPT_SDK_DEVICE_PASS profile={SDK_PROFILE} version={SDK_VERSION} "
            f"abi=2 extension=1 tests={','.join(SDK_TESTS)} run-id={run_id}")
