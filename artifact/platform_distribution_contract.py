#!/usr/bin/env python3
"""Current ABI2 alpha.3 platform-distribution identity and asset contract.

This module contains only prepublication identity: product/revision names and
the exact asset inventory.  Published hashes and observations belong to the
separate immutable publication-receipt contract and must never be introduced
here, because the current producer has to exist before those values do.
"""

from __future__ import annotations


PLATFORM_DISTRIBUTION_SCHEMA_VERSION = 1
PLATFORM_DISTRIBUTION_KIND = "qperiapt.abi2_platform_distribution"
ANDROID_DEVICE_PROOF_SCHEMA_VERSION = 6

PRODUCT_VERSION = "0.1.0-alpha.3"
DISTRIBUTION_REVISION = "r1"
RELEASE_TAG = f"abi2-platforms-v{PRODUCT_VERSION}-{DISTRIBUTION_REVISION}"
RELEASE_URL = f"https://github.com/billlza/q-periapt/releases/tag/{RELEASE_TAG}"

RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
CANDIDATE_SUMS = "CANDIDATE_SHA256SUMS"

ANDROID_AAR = f"q-periapt-android-{PRODUCT_VERSION}.aar"
ANDROID_MANIFEST = f"q-periapt-android-{PRODUCT_VERSION}-MANIFEST.json"
ANDROID_RUNTIME_BUNDLE = (
    f"q-periapt-android-{PRODUCT_VERSION}-16k-runtime-evidence.zip"
)
LINUX_X86_64 = (
    f"q-periapt-c-abi2-{PRODUCT_VERSION}-x86_64-unknown-linux-gnu.tar.gz"
)
LINUX_AARCH64 = (
    f"q-periapt-c-abi2-{PRODUCT_VERSION}-aarch64-unknown-linux-gnu.tar.gz"
)
WINDOWS_X86_64 = (
    f"q-periapt-c-abi2-{PRODUCT_VERSION}-x86_64-pc-windows-msvc.zip"
)

# Exact order used by the tag-bound candidate workflow and its one shared
# provenance statement.  The runtime bundle is assembled locally afterwards
# and therefore is deliberately absent from this CI-candidate set.
PLATFORM_CANDIDATE_ASSETS = (
    ANDROID_AAR,
    ANDROID_MANIFEST,
    LINUX_X86_64,
    LINUX_AARCH64,
    WINDOWS_X86_64,
)
PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS = (
    *PLATFORM_CANDIDATE_ASSETS,
    CANDIDATE_SUMS,
)

PLATFORM_INPUT_ASSETS = frozenset(
    {
        ANDROID_AAR,
        ANDROID_MANIFEST,
        ANDROID_RUNTIME_BUNDLE,
        LINUX_X86_64,
        LINUX_AARCH64,
        WINDOWS_X86_64,
    }
)
PLATFORM_RELEASE_FILES = PLATFORM_INPUT_ASSETS | {RELEASE_MANIFEST, RELEASE_SUMS}
