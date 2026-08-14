#!/usr/bin/env python3
"""Frozen alpha.3 platform publication-receipt contract.

The candidate state intentionally has no remote-publication fields.  Their
absence means that remote verification has not been recorded, not that a
release was observed to be absent.  Published sizes and digests are learned
from the eventual receipt and are accepted only when every related record
cross-links to the same bytes.
"""

from __future__ import annotations

import datetime as dt
import re
from types import MappingProxyType


PLATFORM_ALPHA3_PUBLICATION_SCHEMA_VERSION = 2
PLATFORM_ALPHA3_PUBLICATION_KIND = (
    "qperiapt.abi2_platform_publication_receipt"
)
PLATFORM_ALPHA3_PUBLICATION_KEY = "platform_alpha3_r1"

PRODUCT_VERSION = "0.1.0-alpha.3"
DISTRIBUTION_REVISION = "r1"
RELEASE_TAG = "abi2-platforms-v0.1.0-alpha.3-r1"
RELEASE_URL = (
    "https://github.com/billlza/q-periapt/releases/tag/"
    "abi2-platforms-v0.1.0-alpha.3-r1"
)
RELEASE_REF = f"refs/tags/{RELEASE_TAG}"
TAG_SUBJECT_URI = f"pkg:github/billlza/q-periapt@{RELEASE_TAG}"

PLATFORM_ALPHA3_STATUS_PENDING = (
    "candidate_verified_pending_release_verification"
)
PLATFORM_ALPHA3_STATUS_VERIFIED = (
    "observed_public_immutable_fresh_download_verified"
)
PLATFORM_ALPHA3_PUBLICATION_BOUNDARY = (
    "Frozen ABI 2 alpha.3 platform publication receipt. The pending state "
    "binds only the annotated tag, exact source identity, and six verified "
    "candidate subjects; absent remote fields are unrecorded, not evidence of "
    "non-publication. The verified state additionally binds the exact eight "
    "public immutable GitHub prerelease assets, release attestation, fresh "
    "redownload and deep verification, API 35 arm64-v8a 16 KiB emulator "
    "runtime evidence, unsigned Windows boundary, and unpublished external "
    "registries. It is a research prerelease, not a production, registry, "
    "store, Authenticode, or physical-device claim. Dynamic digests provide "
    "Level-1 accidental-mismatch detection within repository-trusted evidence; "
    "they do not attest a hostile builder or host."
)

RELEASE_MANIFEST = "PLATFORM_DISTRIBUTION.json"
RELEASE_SUMS = "SHA256SUMS"
CANDIDATE_SUMS = "CANDIDATE_SHA256SUMS"
ANDROID_AAR = "q-periapt-android-0.1.0-alpha.3.aar"
ANDROID_MANIFEST = "q-periapt-android-0.1.0-alpha.3-MANIFEST.json"
ANDROID_RUNTIME_BUNDLE = (
    "q-periapt-android-0.1.0-alpha.3-16k-runtime-evidence.zip"
)
LINUX_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.3-x86_64-unknown-linux-gnu.tar.gz"
)
LINUX_AARCH64 = (
    "q-periapt-c-abi2-0.1.0-alpha.3-aarch64-unknown-linux-gnu.tar.gz"
)
WINDOWS_X86_64 = (
    "q-periapt-c-abi2-0.1.0-alpha.3-x86_64-pc-windows-msvc.zip"
)

# The order is the tag-bound candidate workflow's attestation order.  It is
# deliberately not normalized to lexical order after publication.
CANDIDATE_SUBJECT_NAMES = (
    ANDROID_AAR,
    ANDROID_MANIFEST,
    LINUX_X86_64,
    LINUX_AARCH64,
    WINDOWS_X86_64,
    CANDIDATE_SUMS,
)
PUBLIC_ASSET_NAMES = tuple(
    sorted(
        (
            RELEASE_MANIFEST,
            RELEASE_SUMS,
            ANDROID_RUNTIME_BUNDLE,
            ANDROID_MANIFEST,
            ANDROID_AAR,
            LINUX_AARCH64,
            WINDOWS_X86_64,
            LINUX_X86_64,
        )
    )
)
CANDIDATE_PUBLIC_ASSET_NAMES = frozenset(CANDIDATE_SUBJECT_NAMES[:-1])

ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION = 2
ANDROID_DEVICE_PROOF_SCHEMA_VERSION = 6
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

CANDIDATE_SIGNER_WORKFLOW = (
    "https://github.com/billlza/q-periapt/.github/workflows/"
    f"abi2-platform-candidate.yml@{RELEASE_REF}"
)
CANDIDATE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
RELEASE_CERTIFICATE_SAN = "https://dotcom.releases.github.com"
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PENDING_OBSERVATION_KEYS = frozenset(
    {"candidate_attestation", "observed_at", "source"}
)
_VERIFIED_OBSERVATION_KEYS = _PENDING_OBSERVATION_KEYS | frozenset(
    {
        "android_runtime_evidence",
        "assets",
        "checksums_sha256",
        "draft",
        "fresh_download_verification",
        "immutable_release",
        "platform_distribution_sha256",
        "prerelease",
        "public_release",
        "published_at",
        "registries",
        "release_asset_verification_count",
        "release_attestation",
        "release_id",
        "windows_distribution",
    }
)


class PlatformAlpha3PublicationContractError(ValueError):
    """An alpha.3 platform publication receipt violates its contract."""


def _fail(message: str) -> None:
    raise PlatformAlpha3PublicationContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
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


def _sha1(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-1")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(f"{label} must be a positive integer")
    return value


def parse_utc_timestamp(value: object, label: str) -> dt.datetime:
    """Parse one exact second-resolution RFC3339 UTC contract timestamp."""

    if not isinstance(value, str):
        _fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PlatformAlpha3PublicationContractError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _validate_source(source_value: object) -> dict[str, str]:
    source = _object(source_value, "platform alpha3 source identity")
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
        "platform alpha3 source identity",
    )
    canonical_source_tree_sha256 = _sha256(
        source["canonical_source_tree_sha256"],
        "platform alpha3 canonical source tree",
    )
    tag_commit = _sha1(source["tag_commit"], "platform alpha3 tag commit")
    tag_object = _sha1(source["tag_object"], "platform alpha3 tag object")
    tag_tree = _sha1(source["tag_tree"], "platform alpha3 tag tree")
    verifier_commit = _sha1(
        source["verifier_commit"], "platform alpha3 verifier commit"
    )
    _require(
        verifier_commit == tag_commit,
        "platform alpha3 verifier commit differs from the tag commit",
    )
    _require(
        tag_object != tag_commit,
        "platform alpha3 release tag must be an annotated tag object",
    )
    return {
        "canonical_source_tree_sha256": canonical_source_tree_sha256,
        "tag_commit": tag_commit,
        "tag_object": tag_object,
        "tag_tree": tag_tree,
        "verifier_commit": verifier_commit,
    }


def _validate_sha256_subject(
    subject_value: object, *, expected_name: str, label: str
) -> str:
    subject = _object(subject_value, label)
    _exact_keys(subject, frozenset({"digest", "name"}), label)
    _require(subject["name"] == expected_name, f"{label} name differs")
    digest = _object(subject["digest"], f"{label} digest")
    _exact_keys(digest, frozenset({"sha256"}), f"{label} digest")
    return _sha256(digest["sha256"], f"{label} digest")


def _validate_candidate_attestation(
    candidate_value: object, *, tag_commit: str
) -> tuple[dict[str, str], dt.datetime]:
    candidate = _object(
        candidate_value, "platform alpha3 candidate attestation"
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
                "verification_record_sha256",
                "verified",
                "verified_at",
                "workflow_run_attempt",
                "workflow_run_id",
            }
        ),
        "platform alpha3 candidate attestation",
    )
    _require(
        candidate["certificate_san"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform alpha3 candidate certificate identity differs",
    )
    _require(
        candidate["predicate_type"] == CANDIDATE_PREDICATE_TYPE,
        "platform alpha3 candidate predicate differs",
    )
    _require(
        candidate["signer_workflow"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform alpha3 candidate signer workflow differs",
    )
    _require(
        candidate["source_ref"] == RELEASE_REF,
        "platform alpha3 candidate source ref differs",
    )
    _require(
        candidate["source_digest"] == tag_commit,
        "platform alpha3 candidate source digest differs from the tag commit",
    )
    _require(
        candidate["verified"] is True,
        "platform alpha3 candidate attestation must be verified",
    )
    _require(
        type(candidate["workflow_run_attempt"]) is int
        and candidate["workflow_run_attempt"] == 1,
        "platform alpha3 candidate workflow run attempt differs",
    )
    _positive_integer(
        candidate["workflow_run_id"],
        "platform alpha3 candidate workflow run id",
    )
    _sha256(
        candidate["verification_record_sha256"],
        "platform alpha3 candidate verification record",
    )
    verified_at = parse_utc_timestamp(
        candidate["verified_at"], "platform alpha3 candidate verified_at"
    )

    subjects_value = candidate["subjects"]
    if not isinstance(subjects_value, list):
        _fail("platform alpha3 candidate subjects must be a JSON array")
    _require(
        len(subjects_value) == len(CANDIDATE_SUBJECT_NAMES),
        "platform alpha3 candidate subject count differs",
    )
    subjects: dict[str, str] = {}
    for index, expected_name in enumerate(CANDIDATE_SUBJECT_NAMES):
        subjects[expected_name] = _validate_sha256_subject(
            subjects_value[index],
            expected_name=expected_name,
            label=f"platform alpha3 candidate subject {index}",
        )
    return subjects, verified_at


def _validate_assets(assets_value: object) -> dict[str, dict[str, object]]:
    if not isinstance(assets_value, list):
        _fail("platform alpha3 public assets must be a JSON array")
    _require(
        len(assets_value) == len(PUBLIC_ASSET_NAMES),
        "platform alpha3 public asset count differs",
    )
    assets: dict[str, dict[str, object]] = {}
    for index, expected_name in enumerate(PUBLIC_ASSET_NAMES):
        label = f"platform alpha3 public asset {index}"
        asset = _object(assets_value[index], label)
        _exact_keys(asset, frozenset({"bytes", "name", "sha256"}), label)
        _require(asset["name"] == expected_name, f"{label} order/name differs")
        size = _positive_integer(asset["bytes"], f"{label} bytes")
        digest = _sha256(asset["sha256"], f"{label} digest")
        assets[expected_name] = {
            "bytes": size,
            "name": expected_name,
            "sha256": digest,
        }
    return assets


def _validate_candidate_asset_crosslinks(
    candidate_subjects: dict[str, str],
    assets: dict[str, dict[str, object]],
) -> None:
    for name in CANDIDATE_PUBLIC_ASSET_NAMES:
        _require(
            candidate_subjects[name] == assets[name]["sha256"],
            f"platform alpha3 candidate/public asset digest differs: {name}",
        )


def _validate_release_attestation(
    attestation_value: object,
    *,
    assets: dict[str, dict[str, object]],
    tag_object: str,
) -> None:
    attestation = _object(
        attestation_value, "platform alpha3 release attestation"
    )
    _exact_keys(
        attestation,
        frozenset(
            {
                "certificate_san",
                "predicate_type",
                "subjects",
                "verification_record_sha256",
                "verified",
            }
        ),
        "platform alpha3 release attestation",
    )
    _require(
        attestation["certificate_san"] == RELEASE_CERTIFICATE_SAN,
        "platform alpha3 release attestation certificate identity differs",
    )
    _require(
        attestation["predicate_type"] == RELEASE_PREDICATE_TYPE,
        "platform alpha3 release attestation predicate differs",
    )
    _require(
        attestation["verified"] is True,
        "platform alpha3 release attestation must be verified",
    )
    _sha256(
        attestation["verification_record_sha256"],
        "platform alpha3 release attestation verification record",
    )
    subjects_value = attestation["subjects"]
    if not isinstance(subjects_value, list):
        _fail("platform alpha3 release attestation subjects must be a JSON array")
    _require(
        len(subjects_value) == len(PUBLIC_ASSET_NAMES) + 1,
        "platform alpha3 release attestation subject count differs",
    )
    tag_subject = _object(
        subjects_value[0], "platform alpha3 release tag subject"
    )
    _exact_keys(
        tag_subject,
        frozenset({"digest", "uri"}),
        "platform alpha3 release tag subject",
    )
    _require(
        tag_subject["uri"] == TAG_SUBJECT_URI,
        "platform alpha3 release tag subject URI differs",
    )
    tag_digest = _object(
        tag_subject["digest"], "platform alpha3 release tag subject digest"
    )
    _exact_keys(
        tag_digest,
        frozenset({"sha1"}),
        "platform alpha3 release tag subject digest",
    )
    _require(
        _sha1(
            tag_digest["sha1"],
            "platform alpha3 release tag subject digest",
        )
        == tag_object,
        "platform alpha3 release tag subject differs from the tag object",
    )
    for index, expected_name in enumerate(PUBLIC_ASSET_NAMES, start=1):
        digest = _validate_sha256_subject(
            subjects_value[index],
            expected_name=expected_name,
            label=f"platform alpha3 release asset subject {index}",
        )
        _require(
            digest == assets[expected_name]["sha256"],
            f"platform alpha3 release/public asset digest differs: {expected_name}",
        )


def _validate_fresh_download(
    fresh_value: object, *, tag_commit: str
) -> dt.datetime:
    fresh = _object(
        fresh_value, "platform alpha3 fresh download verification"
    )
    _exact_keys(
        fresh,
        frozenset(
            {
                "asset_count",
                "deep_distribution_verified",
                "record_sha256",
                "verified_at",
                "verifier_commit",
            }
        ),
        "platform alpha3 fresh download verification",
    )
    _require(
        type(fresh["asset_count"]) is int
        and fresh["asset_count"] == len(PUBLIC_ASSET_NAMES),
        "platform alpha3 fresh download asset count differs",
    )
    _require(
        fresh["deep_distribution_verified"] is True,
        "platform alpha3 fresh download must pass deep distribution verification",
    )
    _sha256(
        fresh["record_sha256"],
        "platform alpha3 fresh download verification record",
    )
    _require(
        fresh["verifier_commit"] == tag_commit,
        "platform alpha3 fresh verifier commit differs from the tag commit",
    )
    return parse_utc_timestamp(
        fresh["verified_at"],
        "platform alpha3 fresh download verified_at",
    )


def _validate_android_runtime(
    runtime_value: object, *, assets: dict[str, dict[str, object]]
) -> None:
    runtime = _object(
        runtime_value, "platform alpha3 Android runtime evidence"
    )
    _exact_keys(
        runtime,
        frozenset(
            {
                "bundle_manifest_sha256",
                "bundle_schema",
                "bundle_sha256",
                "device_abi",
                "device_kind",
                "device_sdk",
                "page_size",
                "proof_schema",
                "proof_sha256",
                "release_mode",
                "tested_aar_manifest_sha256",
                "tested_aar_sha256",
            }
        ),
        "platform alpha3 Android runtime evidence",
    )
    _require(
        type(runtime["bundle_schema"]) is int
        and runtime["bundle_schema"]
        == ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "platform alpha3 Android runtime bundle schema differs",
    )
    _require(
        type(runtime["proof_schema"]) is int
        and runtime["proof_schema"] == ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "platform alpha3 Android runtime proof schema differs",
    )
    _require(
        runtime["device_kind"] == "emulator"
        and runtime["device_abi"] == "arm64-v8a"
        and type(runtime["device_sdk"]) is int
        and runtime["device_sdk"] == 35
        and type(runtime["page_size"]) is int
        and runtime["page_size"] == 16_384
        and runtime["release_mode"] is True,
        "platform alpha3 Android runtime device boundary differs",
    )
    bundle_sha256 = _sha256(
        runtime["bundle_sha256"],
        "platform alpha3 Android runtime bundle",
    )
    tested_aar_sha256 = _sha256(
        runtime["tested_aar_sha256"],
        "platform alpha3 Android tested AAR",
    )
    tested_aar_manifest_sha256 = _sha256(
        runtime["tested_aar_manifest_sha256"],
        "platform alpha3 Android tested AAR manifest",
    )
    _sha256(
        runtime["bundle_manifest_sha256"],
        "platform alpha3 Android runtime bundle manifest",
    )
    _sha256(
        runtime["proof_sha256"],
        "platform alpha3 Android runtime proof",
    )
    _require(
        bundle_sha256 == assets[ANDROID_RUNTIME_BUNDLE]["sha256"],
        "platform alpha3 Android bundle/public asset digest differs",
    )
    _require(
        tested_aar_sha256 == assets[ANDROID_AAR]["sha256"],
        "platform alpha3 Android tested/public AAR digest differs",
    )
    _require(
        tested_aar_manifest_sha256 == assets[ANDROID_MANIFEST]["sha256"],
        "platform alpha3 Android tested/public manifest digest differs",
    )


def _validate_windows_and_registries(observation: dict[str, object]) -> None:
    windows = _object(
        observation["windows_distribution"],
        "platform alpha3 Windows distribution",
    )
    _exact_keys(
        windows,
        frozenset({"authenticode_signed", "release_class"}),
        "platform alpha3 Windows distribution",
    )
    _require(
        windows
        == {
            "authenticode_signed": False,
            "release_class": WINDOWS_RELEASE_CLASS,
        },
        "platform alpha3 Windows signing boundary differs",
    )
    registries = _object(
        observation["registries"], "platform alpha3 registries"
    )
    _exact_keys(
        registries,
        frozenset(REGISTRY_STATES),
        "platform alpha3 registries",
    )
    _require(
        registries == REGISTRY_STATES,
        "platform alpha3 registry publication state differs",
    )


def validate_alpha3_publication_receipt(receipt_value: object) -> None:
    """Validate one frozen alpha.3 publication receipt without network I/O."""

    receipt = _object(
        receipt_value, "platform alpha3 publication receipt"
    )
    _exact_keys(
        receipt,
        frozenset(
            {
                "boundary",
                "identity",
                "kind",
                "observation",
                "schema_version",
                "status",
            }
        ),
        "platform alpha3 publication receipt",
    )
    _require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"]
        == PLATFORM_ALPHA3_PUBLICATION_SCHEMA_VERSION,
        "platform alpha3 publication receipt schema differs",
    )
    _require(
        receipt["kind"] == PLATFORM_ALPHA3_PUBLICATION_KIND,
        "platform alpha3 publication receipt kind differs",
    )
    _require(
        receipt["boundary"] == PLATFORM_ALPHA3_PUBLICATION_BOUNDARY,
        "platform alpha3 publication boundary differs",
    )
    identity = _object(
        receipt["identity"], "platform alpha3 publication identity"
    )
    _exact_keys(
        identity,
        frozenset(
            {
                "distribution_revision",
                "product_version",
                "release_tag",
                "release_url",
            }
        ),
        "platform alpha3 publication identity",
    )
    _require(
        identity
        == {
            "distribution_revision": DISTRIBUTION_REVISION,
            "product_version": PRODUCT_VERSION,
            "release_tag": RELEASE_TAG,
            "release_url": RELEASE_URL,
        },
        "platform alpha3 publication identity differs",
    )

    status = receipt["status"]
    _require(
        isinstance(status, str),
        "platform alpha3 publication status must be a string",
    )
    _require(
        status
        in {
            PLATFORM_ALPHA3_STATUS_PENDING,
            PLATFORM_ALPHA3_STATUS_VERIFIED,
        },
        f"platform alpha3 publication status is unknown: {status!r}",
    )
    observation = _object(
        receipt["observation"], "platform alpha3 publication observation"
    )
    expected_observation_keys = (
        _VERIFIED_OBSERVATION_KEYS
        if status == PLATFORM_ALPHA3_STATUS_VERIFIED
        else _PENDING_OBSERVATION_KEYS
    )
    _exact_keys(
        observation,
        expected_observation_keys,
        "platform alpha3 publication observation",
    )
    observed_at = parse_utc_timestamp(
        observation["observed_at"], "platform alpha3 observed_at"
    )
    source = _validate_source(observation["source"])
    candidate_subjects, candidate_verified_at = (
        _validate_candidate_attestation(
            observation["candidate_attestation"],
            tag_commit=source["tag_commit"],
        )
    )
    _require(
        candidate_verified_at <= observed_at,
        "platform alpha3 candidate verification postdates observation",
    )

    if status == PLATFORM_ALPHA3_STATUS_PENDING:
        return

    _require(
        observation["draft"] is False
        and observation["prerelease"] is True
        and observation["public_release"] is True
        and observation["immutable_release"] is True,
        "platform alpha3 verified release state differs",
    )
    _positive_integer(
        observation["release_id"], "platform alpha3 GitHub release id"
    )
    _require(
        type(observation["release_asset_verification_count"]) is int
        and observation["release_asset_verification_count"]
        == len(PUBLIC_ASSET_NAMES),
        "platform alpha3 release asset verification count differs",
    )
    published_at = parse_utc_timestamp(
        observation["published_at"], "platform alpha3 published_at"
    )
    assets = _validate_assets(observation["assets"])
    _validate_candidate_asset_crosslinks(candidate_subjects, assets)

    platform_distribution_sha256 = _sha256(
        observation["platform_distribution_sha256"],
        "platform alpha3 distribution manifest",
    )
    checksums_sha256 = _sha256(
        observation["checksums_sha256"],
        "platform alpha3 release checksums",
    )
    _require(
        platform_distribution_sha256
        == assets[RELEASE_MANIFEST]["sha256"],
        "platform alpha3 distribution manifest/public asset digest differs",
    )
    _require(
        checksums_sha256 == assets[RELEASE_SUMS]["sha256"],
        "platform alpha3 checksum/public asset digest differs",
    )
    _validate_release_attestation(
        observation["release_attestation"],
        assets=assets,
        tag_object=source["tag_object"],
    )
    fresh_verified_at = _validate_fresh_download(
        observation["fresh_download_verification"],
        tag_commit=source["tag_commit"],
    )
    _validate_android_runtime(
        observation["android_runtime_evidence"], assets=assets
    )
    _validate_windows_and_registries(observation)
    _require(
        candidate_verified_at <= published_at,
        "platform alpha3 publication predates candidate verification",
    )
    _require(
        published_at <= fresh_verified_at <= observed_at,
        "platform alpha3 publication/fresh/observation timestamps are out of order",
    )
