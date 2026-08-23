#!/usr/bin/env python3
"""Frozen 0.1.3 stable platform publication-receipt contract.

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

import platform_distribution_contract as candidate_contract


PLATFORM_V0_1_3_PUBLICATION_SCHEMA_VERSION = 3
PLATFORM_V0_1_3_PUBLICATION_KIND = (
    "qperiapt.abi2_platform_publication_receipt"
)
PLATFORM_V0_1_3_PUBLICATION_KEY = "platform_v0_1_3"

PRODUCT_VERSION = candidate_contract.PRODUCT_VERSION
DISTRIBUTION_REVISION = candidate_contract.DISTRIBUTION_REVISION
RELEASE_TAG = candidate_contract.RELEASE_TAG
RELEASE_URL = candidate_contract.RELEASE_URL
RELEASE_REF = f"refs/tags/{RELEASE_TAG}"
TAG_SUBJECT_URI = f"pkg:github/billlza/q-periapt@{RELEASE_TAG}"

PLATFORM_V0_1_3_STATUS_PENDING = (
    "candidate_verified_pending_release_verification"
)
PLATFORM_V0_1_3_STATUS_VERIFIED = (
    "observed_public_immutable_fresh_download_verified"
)
PLATFORM_V0_1_3_PUBLICATION_BOUNDARY = (
    "Frozen ABI 2 0.1.3 stable platform publication receipt. The pending state "
    "binds the annotated tag, exact source identity, the final seven-asset local "
    "release candidate, and one verified four-product candidate attestation "
    "covering exact-R binary-CT, six-language CodeQL runs and zero-result "
    "analyses, plus an empty main-ref open-alert observation; absent remote "
    "fields are unrecorded, not evidence of "
    "non-publication. The verified state additionally binds the exact seven "
    "public immutable GitHub release assets, release attestation, fresh "
    "redownload and deep verification, API 35 arm64-v8a 16 KiB emulator "
    "runtime evidence and unpublished external registries. Windows is excluded "
    "from the formal stable asset set until a signed publication boundary "
    "exists. It does not claim registry or store publication, Windows support, "
    "physical-device coverage, or anonymous download "
    "availability; the "
    "GitHub CLI observation uses the source-pinned executable, exactly one "
    "bounded credential, a minimal environment, and empty private "
    "configuration. Dynamic "
    "digests provide "
    "Level-1 accidental-mismatch detection within repository-trusted evidence; "
    "they do not attest a hostile builder or host."
)

RELEASE_MANIFEST = candidate_contract.RELEASE_MANIFEST
RELEASE_SUMS = candidate_contract.RELEASE_SUMS
CANDIDATE_SUMS = candidate_contract.CANDIDATE_SUMS
ANDROID_AAR = candidate_contract.ANDROID_AAR
ANDROID_MANIFEST = candidate_contract.ANDROID_MANIFEST
ANDROID_RUNTIME_BUNDLE = candidate_contract.ANDROID_RUNTIME_BUNDLE
LINUX_X86_64 = candidate_contract.LINUX_X86_64
LINUX_AARCH64 = candidate_contract.LINUX_AARCH64
# The order is the tag-bound candidate workflow's attestation order.  It is
# deliberately not normalized to lexical order after publication.
CANDIDATE_SUBJECT_NAMES = candidate_contract.PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS
PUBLIC_ASSET_NAMES = candidate_contract.PUBLIC_ASSET_NAMES
PUBLIC_ASSET_CONTENT_TYPES = candidate_contract.PUBLIC_ASSET_CONTENT_TYPES
CANDIDATE_PUBLIC_ASSET_NAMES = frozenset(candidate_contract.PLATFORM_CANDIDATE_ASSETS)

ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION = (
    candidate_contract.ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION
)
ANDROID_DEVICE_PROOF_SCHEMA_VERSION = (
    candidate_contract.ANDROID_DEVICE_PROOF_SCHEMA_VERSION
)
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
MAX_WORKFLOW_RUN_ID = (1 << 63) - 1
MAX_WORKFLOW_RUN_ATTEMPT = (1 << 31) - 1

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PENDING_OBSERVATION_KEYS = frozenset(
    {
        "assembly_receipt_sha256",
        "candidate_attestation",
        "observed_at",
        "release_candidate",
        "source",
    }
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
    }
)


class PlatformV013PublicationContractError(ValueError):
    """An 0.1.3 stable platform publication receipt violates its contract."""


def _fail(message: str) -> None:
    raise PlatformV013PublicationContractError(message)


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
        raise PlatformV013PublicationContractError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _validate_source(source_value: object) -> dict[str, object]:
    source = _object(source_value, "platform v0_1_3 source identity")
    _exact_keys(
        source,
        frozenset(
            {
                "canonical_source_tree_sha256",
                "source_date_epoch",
                "source_parent_commit",
                "tag_commit",
                "tag_object",
                "tag_tree",
                "verifier_commit",
            }
        ),
        "platform v0_1_3 source identity",
    )
    canonical_source_tree_sha256 = _sha256(
        source["canonical_source_tree_sha256"],
        "platform v0_1_3 canonical source tree",
    )
    source_parent_commit = _sha1(
        source["source_parent_commit"],
        "platform v0_1_3 source parent commit",
    )
    source_date_epoch = _positive_integer(
        source["source_date_epoch"],
        "platform v0_1_3 source epoch",
    )
    _require(
        315_532_800 <= source_date_epoch <= 0xFFFFFFFF,
        "platform v0_1_3 source epoch is out of range",
    )
    tag_commit = _sha1(source["tag_commit"], "platform v0_1_3 tag commit")
    tag_object = _sha1(source["tag_object"], "platform v0_1_3 tag object")
    tag_tree = _sha1(source["tag_tree"], "platform v0_1_3 tag tree")
    verifier_commit = _sha1(
        source["verifier_commit"], "platform v0_1_3 verifier commit"
    )
    _require(
        source_parent_commit != tag_commit,
        "platform v0_1_3 tag commit must differ from its source parent",
    )
    _require(
        verifier_commit == tag_commit,
        "platform v0_1_3 verifier commit differs from the tag commit",
    )
    _require(
        tag_object != tag_commit,
        "platform v0_1_3 release tag must be an annotated tag object",
    )
    return {
        "canonical_source_tree_sha256": canonical_source_tree_sha256,
        "source_date_epoch": source_date_epoch,
        "source_parent_commit": source_parent_commit,
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
    candidate_value: object, *, tag_commit: str, source_parent_commit: str
) -> tuple[dict[str, str], dt.datetime]:
    candidate = _object(
        candidate_value, "platform v0_1_3 candidate attestation"
    )
    _exact_keys(
        candidate,
        frozenset(
            {
                "certificate_san",
                "predicate_type",
                "security_gate",
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
        "platform v0_1_3 candidate attestation",
    )
    _require(
        candidate["certificate_san"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform v0_1_3 candidate certificate identity differs",
    )
    _require(
        candidate["predicate_type"] == CANDIDATE_PREDICATE_TYPE,
        "platform v0_1_3 candidate predicate differs",
    )
    _require(
        candidate["signer_workflow"] == CANDIDATE_SIGNER_WORKFLOW,
        "platform v0_1_3 candidate signer workflow differs",
    )
    _require(
        candidate["source_ref"] == RELEASE_REF,
        "platform v0_1_3 candidate source ref differs",
    )
    _require(
        candidate["source_digest"] == tag_commit,
        "platform v0_1_3 candidate source digest differs from the tag commit",
    )
    _require(
        candidate["verified"] is True,
        "platform v0_1_3 candidate attestation must be verified",
    )
    workflow_run_attempt = _positive_integer(
        candidate["workflow_run_attempt"],
        "platform v0_1_3 candidate workflow run attempt",
    )
    _require(
        workflow_run_attempt <= MAX_WORKFLOW_RUN_ATTEMPT,
        "platform v0_1_3 candidate workflow run attempt is too large",
    )
    workflow_run_id = _positive_integer(
        candidate["workflow_run_id"],
        "platform v0_1_3 candidate workflow run id",
    )
    _require(
        workflow_run_id <= MAX_WORKFLOW_RUN_ID,
        "platform v0_1_3 candidate workflow run id is too large",
    )
    _sha256(
        candidate["verification_record_sha256"],
        "platform v0_1_3 candidate verification record",
    )
    verified_at = parse_utc_timestamp(
        candidate["verified_at"], "platform v0_1_3 candidate verified_at"
    )

    subjects_value = candidate["subjects"]
    if not isinstance(subjects_value, list):
        _fail("platform v0_1_3 candidate subjects must be a JSON array")
    _require(
        len(subjects_value) == len(CANDIDATE_SUBJECT_NAMES),
        "platform v0_1_3 candidate subject count differs",
    )
    subjects: dict[str, str] = {}
    for index, expected_name in enumerate(CANDIDATE_SUBJECT_NAMES):
        subjects[expected_name] = _validate_sha256_subject(
            subjects_value[index],
            expected_name=expected_name,
            label=f"platform v0_1_3 candidate subject {index}",
        )
    security_projection = _object(
        candidate["security_gate"],
        "platform v0_1_3 source security gate projection",
    )
    _exact_keys(
        security_projection,
        frozenset(
            {
                "code_scanning",
                "kind",
                "observation_tools",
                "receipt_sha256",
                "repository",
                "schema_version",
                "source_parent_commit",
                "tag_commit",
                "workflows",
            }
        ),
        "platform v0_1_3 source security gate projection",
    )
    receipt_sha256 = _sha256(
        security_projection["receipt_sha256"],
        "platform v0_1_3 source security gate receipt",
    )
    _require(
        receipt_sha256 == subjects[candidate_contract.SOURCE_SECURITY_GATE],
        "platform v0_1_3 source security gate digest differs from its subject",
    )
    gate_document = {
        key: value
        for key, value in security_projection.items()
        if key != "receipt_sha256"
    }
    try:
        candidate_contract.validate_source_security_gate(
            gate_document,
            expected_tag_commit=tag_commit,
            expected_source_parent_commit=source_parent_commit,
        )
    except candidate_contract.PlatformDistributionContractError as exc:
        raise PlatformV013PublicationContractError(str(exc)) from exc
    return subjects, verified_at


def _validate_assets(assets_value: object) -> dict[str, dict[str, object]]:
    if not isinstance(assets_value, list):
        _fail("platform v0_1_3 public assets must be a JSON array")
    _require(
        len(assets_value) == len(PUBLIC_ASSET_NAMES),
        "platform v0_1_3 public asset count differs",
    )
    assets: dict[str, dict[str, object]] = {}
    for index, expected_name in enumerate(PUBLIC_ASSET_NAMES):
        label = f"platform v0_1_3 public asset {index}"
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
            f"platform v0_1_3 candidate/public asset digest differs: {name}",
        )


def _validate_release_candidate(
    candidate_value: object,
    *,
    candidate_subjects: dict[str, str],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    try:
        candidate = candidate_contract.validate_release_candidate_projection(
            candidate_value
        )
    except candidate_contract.PlatformDistributionContractError as exc:
        raise PlatformV013PublicationContractError(str(exc)) from exc
    assets = {
        asset["name"]: asset for asset in candidate["assets"]
    }
    _validate_candidate_asset_crosslinks(candidate_subjects, assets)
    return candidate, assets


def _validate_release_attestation(
    attestation_value: object,
    *,
    assets: dict[str, dict[str, object]],
    tag_object: str,
) -> None:
    attestation = _object(
        attestation_value, "platform v0_1_3 release attestation"
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
        "platform v0_1_3 release attestation",
    )
    _require(
        attestation["certificate_san"] == RELEASE_CERTIFICATE_SAN,
        "platform v0_1_3 release attestation certificate identity differs",
    )
    _require(
        attestation["predicate_type"] == RELEASE_PREDICATE_TYPE,
        "platform v0_1_3 release attestation predicate differs",
    )
    _require(
        attestation["verified"] is True,
        "platform v0_1_3 release attestation must be verified",
    )
    _sha256(
        attestation["verification_record_sha256"],
        "platform v0_1_3 release attestation verification record",
    )
    subjects_value = attestation["subjects"]
    if not isinstance(subjects_value, list):
        _fail("platform v0_1_3 release attestation subjects must be a JSON array")
    _require(
        len(subjects_value) == len(PUBLIC_ASSET_NAMES) + 1,
        "platform v0_1_3 release attestation subject count differs",
    )
    tag_subject = _object(
        subjects_value[0], "platform v0_1_3 release tag subject"
    )
    _exact_keys(
        tag_subject,
        frozenset({"digest", "uri"}),
        "platform v0_1_3 release tag subject",
    )
    _require(
        tag_subject["uri"] == TAG_SUBJECT_URI,
        "platform v0_1_3 release tag subject URI differs",
    )
    tag_digest = _object(
        tag_subject["digest"], "platform v0_1_3 release tag subject digest"
    )
    _exact_keys(
        tag_digest,
        frozenset({"sha1"}),
        "platform v0_1_3 release tag subject digest",
    )
    _require(
        _sha1(
            tag_digest["sha1"],
            "platform v0_1_3 release tag subject digest",
        )
        == tag_object,
        "platform v0_1_3 release tag subject differs from the tag object",
    )
    for index, expected_name in enumerate(PUBLIC_ASSET_NAMES, start=1):
        digest = _validate_sha256_subject(
            subjects_value[index],
            expected_name=expected_name,
            label=f"platform v0_1_3 release asset subject {index}",
        )
        _require(
            digest == assets[expected_name]["sha256"],
            f"platform v0_1_3 release/public asset digest differs: {expected_name}",
        )


def _validate_fresh_download(
    fresh_value: object, *, tag_commit: str
) -> dt.datetime:
    fresh = _object(
        fresh_value, "platform v0_1_3 fresh download verification"
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
        "platform v0_1_3 fresh download verification",
    )
    _require(
        type(fresh["asset_count"]) is int
        and fresh["asset_count"] == len(PUBLIC_ASSET_NAMES),
        "platform v0_1_3 fresh download asset count differs",
    )
    _require(
        fresh["deep_distribution_verified"] is True,
        "platform v0_1_3 fresh download must pass deep distribution verification",
    )
    _sha256(
        fresh["record_sha256"],
        "platform v0_1_3 fresh download verification record",
    )
    _require(
        fresh["verifier_commit"] == tag_commit,
        "platform v0_1_3 fresh verifier commit differs from the tag commit",
    )
    return parse_utc_timestamp(
        fresh["verified_at"],
        "platform v0_1_3 fresh download verified_at",
    )


def _validate_android_runtime(
    runtime_value: object, *, assets: dict[str, dict[str, object]]
) -> None:
    runtime = _object(
        runtime_value, "platform v0_1_3 Android runtime evidence"
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
        "platform v0_1_3 Android runtime evidence",
    )
    _require(
        type(runtime["bundle_schema"]) is int
        and runtime["bundle_schema"]
        == ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "platform v0_1_3 Android runtime bundle schema differs",
    )
    _require(
        type(runtime["proof_schema"]) is int
        and runtime["proof_schema"] == ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "platform v0_1_3 Android runtime proof schema differs",
    )
    _require(
        runtime["device_kind"] == "emulator"
        and runtime["device_abi"] == "arm64-v8a"
        and type(runtime["device_sdk"]) is int
        and runtime["device_sdk"] == 35
        and type(runtime["page_size"]) is int
        and runtime["page_size"] == 16_384
        and runtime["release_mode"] is True,
        "platform v0_1_3 Android runtime device boundary differs",
    )
    bundle_sha256 = _sha256(
        runtime["bundle_sha256"],
        "platform v0_1_3 Android runtime bundle",
    )
    tested_aar_sha256 = _sha256(
        runtime["tested_aar_sha256"],
        "platform v0_1_3 Android tested AAR",
    )
    tested_aar_manifest_sha256 = _sha256(
        runtime["tested_aar_manifest_sha256"],
        "platform v0_1_3 Android tested AAR manifest",
    )
    _sha256(
        runtime["bundle_manifest_sha256"],
        "platform v0_1_3 Android runtime bundle manifest",
    )
    _sha256(
        runtime["proof_sha256"],
        "platform v0_1_3 Android runtime proof",
    )
    _require(
        bundle_sha256 == assets[ANDROID_RUNTIME_BUNDLE]["sha256"],
        "platform v0_1_3 Android bundle/public asset digest differs",
    )
    _require(
        tested_aar_sha256 == assets[ANDROID_AAR]["sha256"],
        "platform v0_1_3 Android tested/public AAR digest differs",
    )
    _require(
        tested_aar_manifest_sha256 == assets[ANDROID_MANIFEST]["sha256"],
        "platform v0_1_3 Android tested/public manifest digest differs",
    )


def _validate_registries(observation: dict[str, object]) -> None:
    registries = _object(
        observation["registries"], "platform v0_1_3 registries"
    )
    _exact_keys(
        registries,
        frozenset(REGISTRY_STATES),
        "platform v0_1_3 registries",
    )
    _require(
        registries == REGISTRY_STATES,
        "platform v0_1_3 registry publication state differs",
    )


def validate_v0_1_3_publication_receipt(receipt_value: object) -> None:
    """Validate one frozen 0.1.3 stable publication receipt without network I/O."""

    receipt = _object(
        receipt_value, "platform v0_1_3 publication receipt"
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
        "platform v0_1_3 publication receipt",
    )
    _require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"]
        == PLATFORM_V0_1_3_PUBLICATION_SCHEMA_VERSION,
        "platform v0_1_3 publication receipt schema differs",
    )
    _require(
        receipt["kind"] == PLATFORM_V0_1_3_PUBLICATION_KIND,
        "platform v0_1_3 publication receipt kind differs",
    )
    _require(
        receipt["boundary"] == PLATFORM_V0_1_3_PUBLICATION_BOUNDARY,
        "platform v0_1_3 publication boundary differs",
    )
    identity = _object(
        receipt["identity"], "platform v0_1_3 publication identity"
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
        "platform v0_1_3 publication identity",
    )
    _require(
        identity
        == {
            "distribution_revision": DISTRIBUTION_REVISION,
            "product_version": PRODUCT_VERSION,
            "release_tag": RELEASE_TAG,
            "release_url": RELEASE_URL,
        },
        "platform v0_1_3 publication identity differs",
    )

    status = receipt["status"]
    _require(
        isinstance(status, str),
        "platform v0_1_3 publication status must be a string",
    )
    _require(
        status
        in {
            PLATFORM_V0_1_3_STATUS_PENDING,
            PLATFORM_V0_1_3_STATUS_VERIFIED,
        },
        f"platform v0_1_3 publication status is unknown: {status!r}",
    )
    observation = _object(
        receipt["observation"], "platform v0_1_3 publication observation"
    )
    expected_observation_keys = (
        _VERIFIED_OBSERVATION_KEYS
        if status == PLATFORM_V0_1_3_STATUS_VERIFIED
        else _PENDING_OBSERVATION_KEYS
    )
    _exact_keys(
        observation,
        expected_observation_keys,
        "platform v0_1_3 publication observation",
    )
    observed_at = parse_utc_timestamp(
        observation["observed_at"], "platform v0_1_3 observed_at"
    )
    source = _validate_source(observation["source"])
    candidate_subjects, candidate_verified_at = (
        _validate_candidate_attestation(
            observation["candidate_attestation"],
            tag_commit=source["tag_commit"],
            source_parent_commit=source["source_parent_commit"],
        )
    )
    release_candidate, release_candidate_assets = _validate_release_candidate(
        observation["release_candidate"],
        candidate_subjects=candidate_subjects,
    )
    _sha256(
        observation["assembly_receipt_sha256"],
        "platform v0_1_3 assembly receipt",
    )
    _require(
        candidate_verified_at <= observed_at,
        "platform v0_1_3 candidate verification postdates observation",
    )

    if status == PLATFORM_V0_1_3_STATUS_PENDING:
        return

    _require(
        observation["draft"] is False
        and observation["prerelease"] is False
        and observation["public_release"] is True
        and observation["immutable_release"] is True,
        "platform v0_1_3 verified release state differs",
    )
    _positive_integer(
        observation["release_id"], "platform v0_1_3 GitHub release id"
    )
    _require(
        type(observation["release_asset_verification_count"]) is int
        and observation["release_asset_verification_count"]
        == len(PUBLIC_ASSET_NAMES),
        "platform v0_1_3 release asset verification count differs",
    )
    published_at = parse_utc_timestamp(
        observation["published_at"], "platform v0_1_3 published_at"
    )
    assets = _validate_assets(observation["assets"])
    _validate_candidate_asset_crosslinks(candidate_subjects, assets)
    for name in PUBLIC_ASSET_NAMES:
        expected = release_candidate_assets[name]
        _require(
            assets[name]
            == {
                "bytes": expected["bytes"],
                "name": name,
                "sha256": expected["sha256"],
            },
            f"platform v0_1_3 remote/release candidate asset differs: {name}",
        )

    platform_distribution_sha256 = _sha256(
        observation["platform_distribution_sha256"],
        "platform v0_1_3 distribution manifest",
    )
    checksums_sha256 = _sha256(
        observation["checksums_sha256"],
        "platform v0_1_3 release checksums",
    )
    _require(
        platform_distribution_sha256
        == assets[RELEASE_MANIFEST]["sha256"],
        "platform v0_1_3 distribution manifest/public asset digest differs",
    )
    _require(
        checksums_sha256 == assets[RELEASE_SUMS]["sha256"],
        "platform v0_1_3 checksum/public asset digest differs",
    )
    _require(
        platform_distribution_sha256
        == release_candidate["platform_distribution_sha256"]
        and checksums_sha256 == release_candidate["checksums_sha256"],
        "platform v0_1_3 verified release candidate digest projection differs",
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
    _require(
        observation["android_runtime_evidence"]
        == release_candidate["android_runtime_evidence"],
        "platform v0_1_3 verified Android release candidate projection differs",
    )
    _validate_registries(observation)
    _require(
        candidate_verified_at <= published_at,
        "platform v0_1_3 publication predates candidate verification",
    )
    _require(
        published_at <= fresh_verified_at <= observed_at,
        "platform v0_1_3 publication/fresh/observation timestamps are out of order",
    )
