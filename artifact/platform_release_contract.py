#!/usr/bin/env python3
"""Pure ABI2 platform-r2 identity and publication-receipt contract."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from types import MappingProxyType


PLATFORM_DISTRIBUTION_SCHEMA_VERSION = 1
PLATFORM_DISTRIBUTION_KIND = "qperiapt.abi2_platform_distribution"
PRODUCT_VERSION = "0.1.0-alpha.2"
DISTRIBUTION_REVISION = "r2"
RELEASE_TAG = "abi2-platforms-v0.1.0-alpha.2-r2"
RELEASE_URL = (
    "https://github.com/billlza/q-periapt/releases/tag/"
    "abi2-platforms-v0.1.0-alpha.2-r2"
)
RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
CANDIDATE_SUMS = "CANDIDATE_SHA256SUMS"
ANDROID_AAR = "q-periapt-android-0.1.0-alpha.2.aar"
ANDROID_MANIFEST = "q-periapt-android-0.1.0-alpha.2-MANIFEST.json"
ANDROID_RUNTIME_BUNDLE = (
    "q-periapt-android-0.1.0-alpha.2-16k-runtime-evidence.zip"
)
LINUX_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz"
)
LINUX_AARCH64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz"
)
WINDOWS_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip"
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

ANDROID_DEVICE_PROOF_SCHEMA_VERSION = 3
PLATFORM_RELEASE_RECEIPT_SCHEMA_VERSION = 1
PLATFORM_RELEASE_RECEIPT_KEY = "platform_r2"
PLATFORM_RELEASE_STATUS_PENDING = (
    "observed_public_immutable_pending_fresh_download"
)
PLATFORM_RELEASE_STATUS_VERIFIED = (
    "observed_public_immutable_fresh_download_verified"
)
PLATFORM_RELEASE_BOUNDARY = (
    "Historical repository-local receipt for the public immutable ABI 2 Android, "
    "GNU/Linux, and unsigned Windows r2 prerelease. It binds the annotated tag, "
    "exact assets, candidate build provenance, release attestation, fresh "
    "redownload, and deep verifier results. Android coverage is API 35 "
    "arm64-v8a 16 KiB emulator only; Windows has no Authenticode publisher "
    "identity; external registries are not published."
)

TAG_OBJECT = "01f120c8072c6b98d8d837a03b8599b3f373e90f"
TAG_COMMIT = "5d1598f0ebf9c61e150e55ff398e457ca11f4629"
TAG_TREE = "e07b37df132032f0586412c43c6c58741723d6f3"
CANONICAL_SOURCE_TREE_SHA256 = (
    "7d1224619ab9992e3e10a6be61351835146473bbbc03c661ce8b5b0825078416"
)
PUBLISHED_AT = "2026-07-17T04:49:05Z"
TAG_SUBJECT_URI = (
    "pkg:github/billlza/q-periapt@abi2-platforms-v0.1.0-alpha.2-r2"
)

PLATFORM_DISTRIBUTION_SHA256 = (
    "8c7ce16c38f71c0b0a572cdb96669481f5929843eb41ad31aa4b10e1ee961dbb"
)
RELEASE_SUMS_SHA256 = (
    "b00bb9b93782679241077a4f97af8c983871d12024721452150924cfd79ec729"
)
CANDIDATE_SUMS_SHA256 = (
    "ac96943c9a6ba59423b68c5679d1520e3db1221ae6e9a7e0414b7d93fb699ac5"
)
ANDROID_BUNDLE_MANIFEST_SHA256 = (
    "3d64bdc325d6207134b347ce003b0307a85640c9dad068cbd4dff1915e59cc14"
)
ANDROID_PROOF_SHA256 = (
    "5cb1b775914141238270c88e1a7214e0d2dcb0e72ab32385283fec5b54ecdbad"
)
RELEASE_ATTESTATION_VERIFICATION_SHA256 = (
    "3bc7950fb33e875b4279c116a94890b8742538fbfeae5c5d58be9fe0ca396b94"
)

CANDIDATE_WORKFLOW_RUN_ID = 29555221955
CANDIDATE_SOURCE_REF = f"refs/tags/{RELEASE_TAG}"
CANDIDATE_SIGNER_WORKFLOW = (
    "https://github.com/billlza/q-periapt/.github/workflows/"
    f"abi2-platform-candidate.yml@{CANDIDATE_SOURCE_REF}"
)
CANDIDATE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"
RELEASE_CERTIFICATE_SAN = "https://dotcom.releases.github.com"

WINDOWS_RELEASE_CLASS = "unsigned_experimental_prerelease"
NOT_PUBLISHED = "not_published"
REGISTRY_STATES = MappingProxyType(
    {
        "crates_io": NOT_PUBLISHED,
        "deb": NOT_PUBLISHED,
        "maven_central": NOT_PUBLISHED,
        "msix": NOT_PUBLISHED,
        "rpm": NOT_PUBLISHED,
    }
)


class PlatformReleaseContractError(ValueError):
    """A captured ABI2 platform publication receipt violates its contract."""


@dataclass(frozen=True, slots=True)
class PublishedAsset:
    """An exact public release asset identity."""

    name: str
    size: int
    sha256: str


PUBLISHED_ASSETS = (
    PublishedAsset(RELEASE_MANIFEST, 4470, PLATFORM_DISTRIBUTION_SHA256),
    PublishedAsset(RELEASE_SUMS, 813, RELEASE_SUMS_SHA256),
    PublishedAsset(
        ANDROID_RUNTIME_BUNDLE,
        3_094_070,
        "7c4246103d58bac661fc8018d0cc160aa07eee99b831e7a90f35f049dc5d71cf",
    ),
    PublishedAsset(
        ANDROID_MANIFEST,
        3_934,
        "9026705524a7df8fb6dbaf545f060d27e9e97a32321fd43a25d8b2f5bd57fdec",
    ),
    PublishedAsset(
        ANDROID_AAR,
        3_535_331,
        "fb0f18496eefb7aee38ac4fecae77a9de666f107251839c4d73f3c24a6620d7d",
    ),
    PublishedAsset(
        LINUX_AARCH64,
        1_367_909,
        "930fa378402ae8b9bdf611674dde81b91eebb088a19a3124f7c935c65b0617f5",
    ),
    PublishedAsset(
        WINDOWS_X86_64,
        1_713_826,
        "6d0336d28f06cb9693ffec1bec86fe106b774c9bd8f082747c072e86786eff8f",
    ),
    PublishedAsset(
        LINUX_X86_64,
        1_413_633,
        "8f38b40aebd2efd1b6d5b007f0bd633f822d16a1f5869f3642147d7a651f906f",
    ),
)
ASSET_BY_NAME = MappingProxyType(
    {asset.name: asset for asset in PUBLISHED_ASSETS}
)


def _fail(message: str) -> None:
    raise PlatformReleaseContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a JSON object with string keys")
    return value


def _exact_keys(
    value: dict[str, object], expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} keys differ: missing={missing!r} extra={extra!r}")


def _asset_records() -> list[dict[str, object]]:
    return [
        {"bytes": asset.size, "name": asset.name, "sha256": asset.sha256}
        for asset in PUBLISHED_ASSETS
    ]


def _sha256_subject(name: str, sha256: str) -> dict[str, object]:
    return {"digest": {"sha256": sha256}, "name": name}


def _candidate_subjects() -> list[dict[str, object]]:
    names_and_hashes = (
        (CANDIDATE_SUMS, CANDIDATE_SUMS_SHA256),
        (ANDROID_MANIFEST, ASSET_BY_NAME[ANDROID_MANIFEST].sha256),
        (ANDROID_AAR, ASSET_BY_NAME[ANDROID_AAR].sha256),
        (LINUX_AARCH64, ASSET_BY_NAME[LINUX_AARCH64].sha256),
        (WINDOWS_X86_64, ASSET_BY_NAME[WINDOWS_X86_64].sha256),
        (LINUX_X86_64, ASSET_BY_NAME[LINUX_X86_64].sha256),
    )
    return [_sha256_subject(name, digest) for name, digest in names_and_hashes]


def _release_subjects() -> list[dict[str, object]]:
    return [
        {"digest": {"sha1": TAG_OBJECT}, "uri": TAG_SUBJECT_URI},
        *[
            _sha256_subject(asset.name, asset.sha256)
            for asset in PUBLISHED_ASSETS
        ],
    ]


def _parse_timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        _fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PlatformReleaseContractError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _validate_attestations(
    observation: dict[str, object], *, verified: bool
) -> None:
    candidate = _object(
        observation["candidate_attestation"], "platform r2 candidate attestation"
    )
    _exact_keys(
        candidate,
        frozenset(
            {
                "certificate_san",
                "predicate_type",
                "signer_workflow",
                "source_digest",
                "source_ref",
                "subjects",
                "verified",
                "workflow_run_id",
            }
        ),
        "platform r2 candidate attestation",
    )
    _require(
        candidate["certificate_san"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform r2 candidate attestation certificate identity differs",
    )
    _require(
        candidate["predicate_type"] == CANDIDATE_PREDICATE_TYPE,
        "platform r2 candidate attestation predicate differs",
    )
    _require(
        candidate["signer_workflow"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform r2 candidate signer workflow differs",
    )
    _require(
        candidate["source_digest"] == TAG_COMMIT,
        "platform r2 candidate source digest differs",
    )
    _require(
        candidate["source_ref"] == CANDIDATE_SOURCE_REF,
        "platform r2 candidate source ref differs",
    )
    _require(
        candidate["workflow_run_id"] == CANDIDATE_WORKFLOW_RUN_ID,
        "platform r2 candidate workflow run differs",
    )
    _require(
        candidate["verified"] is verified,
        "platform r2 candidate attestation state is inconsistent",
    )
    expected_candidate_subjects = _candidate_subjects() if verified else []
    _require(
        candidate["subjects"] == expected_candidate_subjects,
        "platform r2 candidate attestation subjects differ",
    )

    release = _object(
        observation["release_attestation"], "platform r2 release attestation"
    )
    _exact_keys(
        release,
        frozenset(
            {
                "certificate_san",
                "predicate_type",
                "subjects",
                "verification_record_sha256",
                "verified",
            }
        ),
        "platform r2 release attestation",
    )
    _require(
        release["certificate_san"] == RELEASE_CERTIFICATE_SAN,
        "platform r2 release attestation certificate identity differs",
    )
    _require(
        release["predicate_type"] == RELEASE_PREDICATE_TYPE,
        "platform r2 release attestation predicate differs",
    )
    _require(
        release["verified"] is verified,
        "platform r2 release attestation state is inconsistent",
    )
    expected_record = RELEASE_ATTESTATION_VERIFICATION_SHA256 if verified else None
    _require(
        release["verification_record_sha256"] == expected_record,
        "platform r2 release attestation verification record differs",
    )
    expected_release_subjects = _release_subjects() if verified else []
    _require(
        release["subjects"] == expected_release_subjects,
        "platform r2 release attestation subjects differ",
    )


def _validate_platform_r2_receipt(receipt_value: object) -> None:
    receipt = _object(receipt_value, "platform r2 publication receipt")
    _exact_keys(
        receipt,
        frozenset({"boundary", "identity", "observation", "schema_version", "status"}),
        "platform r2 publication receipt",
    )
    _require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == PLATFORM_RELEASE_RECEIPT_SCHEMA_VERSION,
        "platform r2 publication receipt schema differs",
    )
    _require(
        receipt["boundary"] == PLATFORM_RELEASE_BOUNDARY,
        "platform r2 publication boundary differs",
    )

    identity = _object(receipt["identity"], "platform r2 publication identity")
    _exact_keys(
        identity,
        frozenset(
            {"distribution_revision", "product_version", "release_tag", "release_url"}
        ),
        "platform r2 publication identity",
    )
    _require(
        identity
        == {
            "distribution_revision": DISTRIBUTION_REVISION,
            "product_version": PRODUCT_VERSION,
            "release_tag": RELEASE_TAG,
            "release_url": RELEASE_URL,
        },
        "platform r2 publication identity differs",
    )

    status = receipt["status"]
    _require(
        status in {PLATFORM_RELEASE_STATUS_PENDING, PLATFORM_RELEASE_STATUS_VERIFIED},
        f"platform r2 publication status is unknown: {status!r}",
    )
    verified = status == PLATFORM_RELEASE_STATUS_VERIFIED

    observation = _object(receipt["observation"], "platform r2 observation")
    _exact_keys(
        observation,
        frozenset(
            {
                "android_runtime_evidence",
                "assets",
                "candidate_attestation",
                "checksums_sha256",
                "deep_distribution_verified",
                "fresh_download_verified",
                "immutable_release",
                "observed_at",
                "platform_distribution_sha256",
                "public_release",
                "published_at",
                "registries",
                "release_asset_verification_count",
                "release_attestation",
                "source",
                "windows_distribution",
            }
        ),
        "platform r2 observation",
    )
    _require(
        observation["public_release"] is True
        and observation["immutable_release"] is True,
        "platform r2 receipt requires a public immutable release",
    )
    _require(
        observation["published_at"] == PUBLISHED_AT,
        "platform r2 publication time differs",
    )
    published_at = _parse_timestamp(observation["published_at"], "published_at")
    observed_at = _parse_timestamp(observation["observed_at"], "observed_at")
    _require(
        observed_at >= published_at,
        "platform r2 observation predates publication",
    )

    expected_fresh = verified
    expected_count = len(PUBLISHED_ASSETS) if verified else 0
    _require(
        observation["fresh_download_verified"] is expected_fresh
        and observation["deep_distribution_verified"] is expected_fresh
        and type(observation["release_asset_verification_count"]) is int
        and observation["release_asset_verification_count"] == expected_count,
        "platform r2 publication state is only partially promoted",
    )
    _require(
        observation["assets"] == _asset_records(),
        "platform r2 public asset set differs",
    )
    _require(
        observation["platform_distribution_sha256"]
        == ASSET_BY_NAME[RELEASE_MANIFEST].sha256,
        "platform r2 distribution-manifest hash differs",
    )
    _require(
        observation["checksums_sha256"] == ASSET_BY_NAME[RELEASE_SUMS].sha256,
        "platform r2 checksum-file hash differs",
    )

    source = _object(observation["source"], "platform r2 source identity")
    _exact_keys(
        source,
        frozenset(
            {
                "canonical_source_tree_sha256",
                "tag_commit",
                "tag_object",
                "tag_tree",
                "verifier_commit",
            }
        ),
        "platform r2 source identity",
    )
    _require(
        source
        == {
            "canonical_source_tree_sha256": CANONICAL_SOURCE_TREE_SHA256,
            "tag_commit": TAG_COMMIT,
            "tag_object": TAG_OBJECT,
            "tag_tree": TAG_TREE,
            "verifier_commit": TAG_COMMIT,
        },
        "platform r2 source identity differs",
    )

    android = _object(
        observation["android_runtime_evidence"],
        "platform r2 Android runtime evidence",
    )
    _exact_keys(
        android,
        frozenset(
            {
                "bundle_manifest_sha256",
                "bundle_sha256",
                "device_abi",
                "device_kind",
                "device_sdk",
                "page_size",
                "proof_schema",
                "proof_sha256",
                "tested_aar_sha256",
            }
        ),
        "platform r2 Android runtime evidence",
    )
    _require(
        android
        == {
            "bundle_manifest_sha256": ANDROID_BUNDLE_MANIFEST_SHA256,
            "bundle_sha256": ASSET_BY_NAME[ANDROID_RUNTIME_BUNDLE].sha256,
            "device_abi": "arm64-v8a",
            "device_kind": "emulator",
            "device_sdk": 35,
            "page_size": 16_384,
            "proof_schema": ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            "proof_sha256": ANDROID_PROOF_SHA256,
            "tested_aar_sha256": ASSET_BY_NAME[ANDROID_AAR].sha256,
        },
        "platform r2 Android runtime evidence differs",
    )

    windows = _object(
        observation["windows_distribution"], "platform r2 Windows distribution"
    )
    _exact_keys(
        windows,
        frozenset({"authenticode_signed", "release_class"}),
        "platform r2 Windows distribution",
    )
    _require(
        windows
        == {
            "authenticode_signed": False,
            "release_class": WINDOWS_RELEASE_CLASS,
        },
        "platform r2 Windows signing boundary differs",
    )

    registries = _object(observation["registries"], "platform r2 registries")
    _require(
        registries == REGISTRY_STATES,
        "platform r2 registry publication state differs",
    )
    _validate_attestations(observation, verified=verified)


def validate_release_publications(manifest: dict[str, object]) -> None:
    """Validate optional captured publication receipts without network I/O."""

    publications_value = manifest.get("release_publications")
    if publications_value is None:
        return
    publications = _object(publications_value, "release_publications")
    unknown = sorted(set(publications) - {PLATFORM_RELEASE_RECEIPT_KEY})
    if unknown:
        _fail(f"release_publications has unknown entries: {unknown!r}")
    if PLATFORM_RELEASE_RECEIPT_KEY in publications:
        _validate_platform_r2_receipt(
            publications[PLATFORM_RELEASE_RECEIPT_KEY]
        )
