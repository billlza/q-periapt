#!/usr/bin/env python3
"""Versioned Apple XCFramework publication receipts and transitions."""

from __future__ import annotations

import datetime as dt
import re

import apple_distribution


APPLE_PUBLICATION_SCHEMA_VERSION = 1
APPLE_PUBLICATION_KIND = "qperiapt.apple_xcframework_publication_receipt"
APPLE_ALPHA2_R1_PUBLICATION_KEY = "apple_alpha2_r1"
APPLE_ALPHA3_R1_PUBLICATION_KEY = "apple_alpha3_r1"
APPLE_PUBLICATION_KEYS = frozenset(
    {APPLE_ALPHA2_R1_PUBLICATION_KEY, APPLE_ALPHA3_R1_PUBLICATION_KEY}
)

APPLE_STATUS_PENDING = "signed_candidate_pending_release_verification"
APPLE_STATUS_VERIFIED = (
    "observed_public_immutable_remote_consumer_verified"
)
APPLE_ALPHA2_R1_BOUNDARY = (
    "Frozen ABI 2 Apple alpha.2 r1 publication receipt. It binds the exact "
    "historical signed static XCFramework ZIP, source commit, Developer ID "
    "identity, four published asset digests, annotated tag, five-subject GitHub "
    "release attestation, immutable GitHub prerelease state, and fresh remote "
    "SwiftPM consumer verification recorded in trusted results. It is not "
    "notarization, App Store, physical-device, or hostile-host evidence."
)
APPLE_ALPHA3_R1_BOUNDARY = (
    "Frozen ABI 2 Apple alpha.3 r1 publication receipt. The pending state binds "
    "the exact signed static XCFramework candidate, source commit, Developer ID "
    "identity, and four candidate asset digests without claiming publication. "
    "The verified state additionally binds the annotated tag, exact five-subject "
    "GitHub release attestation, public immutable GitHub prerelease, and fresh "
    "remote SwiftPM consumer verification. It is not notarization, App Store, "
    "physical-device, or hostile-host evidence."
)

APPLE_ALPHA2_R1_IDENTITY = {
    "distribution_revision": "r1",
    "product_version": "0.1.0-alpha.2",
    "release_tag": "v0.1.0-alpha.2-r1",
    "release_url": (
        "https://github.com/billlza/q-periapt/releases/tag/"
        "v0.1.0-alpha.2-r1"
    ),
}
APPLE_ALPHA3_R1_IDENTITY = {
    "distribution_revision": "r1",
    "product_version": "0.1.0-alpha.3",
    "release_tag": "v0.1.0-alpha.3-r1",
    "release_url": (
        "https://github.com/billlza/q-periapt/releases/tag/"
        "v0.1.0-alpha.3-r1"
    ),
}
APPLE_XCFRAMEWORK_ARTIFACT_PATH = "CQPeriapt.xcframework.zip"
APPLE_ORIGIN_IDENTITY_CLASS = "Developer ID Application"
APPLE_DISTRIBUTION_ASSET_PATH = "APPLE_DISTRIBUTION.json"
APPLE_MANIFEST_ASSET_PATH = "MANIFEST.json"
APPLE_CHECKSUMS_ASSET_PATH = "SHA256SUMS"
APPLE_RELEASE_CERTIFICATE_SAN = "https://dotcom.releases.github.com"
APPLE_RELEASE_PREDICATE_TYPE = (
    "https://in-toto.io/attestation/release/v0.2"
)
APPLE_TAG_SUBJECT_PREFIX = "pkg:github/billlza/q-periapt@"

_BASE_RECEIPT_KEYS = frozenset(
    {"boundary", "distribution", "identity", "kind", "schema_version", "status"}
)
_VERIFIED_RECEIPT_KEYS = _BASE_RECEIPT_KEYS | frozenset({"publication"})
_IDENTITY_KEYS = frozenset(
    {"distribution_revision", "product_version", "release_tag", "release_url"}
)
_PUBLICATION_KEYS = frozenset(
    {
        "draft",
        "immutable_release",
        "observed_at",
        "prerelease",
        "public_release",
        "published_at",
        "release_attestation",
        "release_id",
        "source",
    }
)
_PUBLICATION_SOURCE_KEYS = frozenset({"tag_commit", "tag_object"})
_RELEASE_ATTESTATION_KEYS = frozenset(
    {
        "certificate_san",
        "predicate_type",
        "subjects",
        "verification_record_sha256",
        "verified",
        "verified_at",
    }
)
_PROMOTION_ONLY_DISTRIBUTION_FIELDS = frozenset(
    {
        "immutable_release",
        "public_release",
        "remote_consumer_verified",
        "remote_verification",
    }
)
_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ApplePublicationContractError(ValueError):
    """An Apple publication receipt or transition violates its contract."""


def _fail(message: str) -> None:
    raise ApplePublicationContractError(message)


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
        _fail(
            f"{label} keys differ: missing={sorted(expected - actual)!r} "
            f"extra={sorted(actual - expected)!r}"
        )


def _sha1(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-1")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def _timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        _fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ApplePublicationContractError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def publication_values_equal(left: object, right: object) -> bool:
    """Compare JSON values recursively without Python bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            publication_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            publication_values_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def frozen_alpha2_r1_distribution() -> dict[str, object]:
    """Return a fresh copy of the exact historical alpha.2 verified projection."""

    return {
        "apple_distribution_evidence_sha256": (
            "5d92029803d66864b1b964ccb539f6e613a97be57b084cc845e178cbcb2b415b"
        ),
        "artifact_path": "CQPeriapt.xcframework.zip",
        "artifact_sha256": (
            "4480061244b5844cd1ff2349c05d261d0455db68c459449be33cbab63c94be0f"
        ),
        "artifact_size": 33_325_898,
        "checksums_sha256": (
            "253a5888eb0f4eaae301ce2b7d59e1554369c4eeaa594f5939cdd6b9b0874e98"
        ),
        "distribution_signed": True,
        "immutable_release": True,
        "manifest_sha256": (
            "0eafcf6989fe40835e9f2550098d1165d958b6bbe27373ba5ead9ee1a1757439"
        ),
        "notarization_applicability": "not_applicable_static_sdk_payload",
        "notarized": False,
        "origin_signature_certificate_sha256": (
            "806673908a3ddcd558dcc8d3ef055085f1fff100bda0acfb2e1315afd652ac8d"
        ),
        "origin_signature_identity_class": "Developer ID Application",
        "origin_signature_team_id": "YKUPL7Z869",
        "public_release": True,
        "release_revision": "r1",
        "release_tag": "v0.1.0-alpha.2-r1",
        "release_url": (
            "https://github.com/billlza/q-periapt/releases/tag/"
            "v0.1.0-alpha.2-r1"
        ),
        "remote_consumer_verified": True,
        "remote_verification": {
            "log_sha256": (
                "a6bfd03d1f9c558d99929ced8e2580c02bb7ea61dd395984c1fcb87be5c14d38"
            ),
            "verified_at": "2026-07-17T05:25:50Z",
            "verifier_commit": "d93a7cab2e00ce1036f6b218eef01bb889cb60a9",
        },
        "source_commit": "5664fd86a617f92b620ea37e7692d3417d0e307d",
        "stapled": False,
        "swiftpm_checksum": (
            "4480061244b5844cd1ff2349c05d261d0455db68c459449be33cbab63c94be0f"
        ),
        "version": "0.1.0-alpha.2",
    }


def _release_attestation_subjects(
    *,
    identity: dict[str, object],
    distribution: dict[str, object],
    tag_object: str,
) -> list[dict[str, object]]:
    release_tag = identity["release_tag"]
    if not isinstance(release_tag, str):
        _fail("Apple release tag must be a string")
    return [
        {
            "digest": {"sha1": tag_object},
            "uri": APPLE_TAG_SUBJECT_PREFIX + release_tag,
        },
        {
            "digest": {
                "sha256": distribution[
                    "apple_distribution_evidence_sha256"
                ]
            },
            "name": APPLE_DISTRIBUTION_ASSET_PATH,
        },
        {
            "digest": {"sha256": distribution["artifact_sha256"]},
            "name": APPLE_XCFRAMEWORK_ARTIFACT_PATH,
        },
        {
            "digest": {"sha256": distribution["manifest_sha256"]},
            "name": APPLE_MANIFEST_ASSET_PATH,
        },
        {
            "digest": {"sha256": distribution["checksums_sha256"]},
            "name": APPLE_CHECKSUMS_ASSET_PATH,
        },
    ]


def frozen_alpha2_r1_publication() -> dict[str, object]:
    """Return the exact verified alpha.2 GitHub publication projection."""

    tag_object = "6fd8d410c078c50906dcaad885a4361e08702fc2"
    return {
        "draft": False,
        "immutable_release": True,
        "observed_at": "2026-08-14T03:00:09Z",
        "prerelease": True,
        "public_release": True,
        "published_at": "2026-07-17T03:16:01Z",
        "release_attestation": {
            "certificate_san": "https://dotcom.releases.github.com",
            "predicate_type": (
                "https://in-toto.io/attestation/release/v0.2"
            ),
            "subjects": [
                {
                    "digest": {"sha1": tag_object},
                    "uri": (
                        "pkg:github/billlza/q-periapt@v0.1.0-alpha.2-r1"
                    ),
                },
                {
                    "digest": {
                        "sha256": (
                            "5d92029803d66864b1b964ccb539f6e613a97be57b084cc845e178cbcb2b415b"
                        )
                    },
                    "name": "APPLE_DISTRIBUTION.json",
                },
                {
                    "digest": {
                        "sha256": (
                            "4480061244b5844cd1ff2349c05d261d0455db68c459449be33cbab63c94be0f"
                        )
                    },
                    "name": "CQPeriapt.xcframework.zip",
                },
                {
                    "digest": {
                        "sha256": (
                            "0eafcf6989fe40835e9f2550098d1165d958b6bbe27373ba5ead9ee1a1757439"
                        )
                    },
                    "name": "MANIFEST.json",
                },
                {
                    "digest": {
                        "sha256": (
                            "253a5888eb0f4eaae301ce2b7d59e1554369c4eeaa594f5939cdd6b9b0874e98"
                        )
                    },
                    "name": "SHA256SUMS",
                },
            ],
            "verification_record_sha256": (
                "1f48b1891211b1bec543a5925fc3561f106d2da6e073e21031c0b06ef17081de"
            ),
            "verified": True,
            "verified_at": "2026-07-17T03:16:02Z",
        },
        "release_id": 355_454_389,
        "source": {
            "tag_commit": "5664fd86a617f92b620ea37e7692d3417d0e307d",
            "tag_object": tag_object,
        },
    }


def _validate_identity(
    identity_value: object,
    *,
    expected: dict[str, str],
    label: str,
) -> dict[str, object]:
    identity = _object(identity_value, label)
    _exact_keys(identity, _IDENTITY_KEYS, label)
    if not publication_values_equal(identity, expected):
        _fail(f"{label} differs from the frozen release identity")
    return identity


def _validate_distribution(
    distribution_value: object,
    *,
    identity: dict[str, object],
    label: str,
) -> dict[str, object]:
    distribution_object = _object(distribution_value, label)
    try:
        distribution = (
            apple_distribution.validate_trusted_results_distribution_shape(
                distribution_object
            )
        )
    except apple_distribution.AppleDistributionError as exc:
        raise ApplePublicationContractError(str(exc)) from exc
    expected_links = {
        "release_revision": identity["distribution_revision"],
        "release_tag": identity["release_tag"],
        "release_url": identity["release_url"],
        "version": identity["product_version"],
    }
    for field, expected in expected_links.items():
        if not publication_values_equal(distribution[field], expected):
            _fail(f"{label} identity cross-link differs at {field}")
    frozen_policy = {
        "artifact_path": APPLE_XCFRAMEWORK_ARTIFACT_PATH,
        "distribution_signed": True,
        "notarization_applicability": "not_applicable_static_sdk_payload",
        "notarized": False,
        "origin_signature_identity_class": APPLE_ORIGIN_IDENTITY_CLASS,
        "stapled": False,
    }
    for field, expected in frozen_policy.items():
        if not publication_values_equal(distribution[field], expected):
            _fail(f"{label} frozen distribution policy differs at {field}")
    return distribution


def _validate_publication(
    publication_value: object,
    *,
    identity: dict[str, object],
    distribution: dict[str, object],
    label: str,
) -> None:
    publication = _object(publication_value, f"{label} publication")
    _exact_keys(publication, _PUBLICATION_KEYS, f"{label} publication")
    expected_release_state = {
        "draft": False,
        "immutable_release": True,
        "prerelease": True,
        "public_release": True,
    }
    for field, expected in expected_release_state.items():
        if not publication_values_equal(publication[field], expected):
            _fail(f"{label} publication field {field} differs")
    if (
        type(publication["release_id"]) is not int
        or publication["release_id"] <= 0
    ):
        _fail(f"{label} publication release_id must be a positive integer")
    if (
        publication["public_release"] != distribution["public_release"]
        or publication["immutable_release"]
        != distribution["immutable_release"]
    ):
        _fail(f"{label} publication/distribution release state differs")

    source = _object(publication["source"], f"{label} publication source")
    _exact_keys(
        source, _PUBLICATION_SOURCE_KEYS, f"{label} publication source"
    )
    tag_object = _sha1(
        source["tag_object"], f"{label} publication tag object"
    )
    tag_commit = _sha1(
        source["tag_commit"], f"{label} publication tag commit"
    )
    if tag_object == tag_commit:
        _fail(f"{label} publication tag must be an annotated tag object")
    if tag_commit != distribution["source_commit"]:
        _fail(f"{label} publication tag/distribution source commit differs")

    attestation = _object(
        publication["release_attestation"],
        f"{label} release attestation",
    )
    _exact_keys(
        attestation,
        _RELEASE_ATTESTATION_KEYS,
        f"{label} release attestation",
    )
    if attestation["certificate_san"] != APPLE_RELEASE_CERTIFICATE_SAN:
        _fail(f"{label} release attestation certificate identity differs")
    if attestation["predicate_type"] != APPLE_RELEASE_PREDICATE_TYPE:
        _fail(f"{label} release attestation predicate differs")
    if attestation["verified"] is not True:
        _fail(f"{label} release attestation must be verified")
    _sha256(
        attestation["verification_record_sha256"],
        f"{label} release attestation verification record",
    )
    expected_subjects = _release_attestation_subjects(
        identity=identity,
        distribution=distribution,
        tag_object=tag_object,
    )
    if not publication_values_equal(attestation["subjects"], expected_subjects):
        _fail(f"{label} release attestation subjects differ")

    published_at = _timestamp(
        publication["published_at"], f"{label} publication published_at"
    )
    attestation_verified_at = _timestamp(
        attestation["verified_at"],
        f"{label} release attestation verified_at",
    )
    remote_verification = _object(
        distribution["remote_verification"],
        f"{label} distribution remote verification",
    )
    remote_verified_at = _timestamp(
        remote_verification["verified_at"],
        f"{label} distribution remote verified_at",
    )
    observed_at = _timestamp(
        publication["observed_at"], f"{label} publication observed_at"
    )
    if not (
        published_at
        <= attestation_verified_at
        <= remote_verified_at
        <= observed_at
    ):
        _fail(f"{label} publication verification timestamps are out of order")


def _validate_receipt(
    receipt_value: object,
    *,
    key: str,
) -> None:
    label = f"Apple publication receipt {key}"
    receipt = _object(receipt_value, label)
    status = receipt.get("status")
    if not isinstance(status, str):
        _fail(f"{label} status must be a string")
    if key == APPLE_ALPHA2_R1_PUBLICATION_KEY:
        if status != APPLE_STATUS_VERIFIED:
            _fail("historical Apple alpha.2 publication status differs")
        expected_identity = APPLE_ALPHA2_R1_IDENTITY
        expected_boundary = APPLE_ALPHA2_R1_BOUNDARY
    elif key == APPLE_ALPHA3_R1_PUBLICATION_KEY:
        if status not in {APPLE_STATUS_PENDING, APPLE_STATUS_VERIFIED}:
            _fail(f"Apple alpha.3 publication status is unknown: {status!r}")
        expected_identity = APPLE_ALPHA3_R1_IDENTITY
        expected_boundary = APPLE_ALPHA3_R1_BOUNDARY
    else:
        _fail(f"unknown Apple publication receipt key: {key!r}")
    expected_receipt_keys = (
        _VERIFIED_RECEIPT_KEYS
        if status == APPLE_STATUS_VERIFIED
        else _BASE_RECEIPT_KEYS
    )
    _exact_keys(receipt, expected_receipt_keys, label)
    if (
        type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != APPLE_PUBLICATION_SCHEMA_VERSION
    ):
        _fail(f"{label} schema differs")
    if receipt["kind"] != APPLE_PUBLICATION_KIND:
        _fail(f"{label} kind differs")

    if receipt["boundary"] != expected_boundary:
        _fail(f"{label} boundary differs")
    identity = _validate_identity(
        receipt["identity"],
        expected=expected_identity,
        label=f"{label} identity",
    )
    distribution = _validate_distribution(
        receipt["distribution"], identity=identity, label=label
    )

    if key == APPLE_ALPHA2_R1_PUBLICATION_KEY:
        if not publication_values_equal(
            distribution, frozen_alpha2_r1_distribution()
        ):
            _fail(
                "historical Apple alpha.2 distribution differs from the frozen receipt"
            )
    if status == APPLE_STATUS_PENDING:
        expected_state = (False, False, False)
    else:
        expected_state = (True, True, True)
    actual_state = (
        distribution["public_release"],
        distribution["immutable_release"],
        distribution["remote_consumer_verified"],
    )
    if actual_state != expected_state:
        _fail("Apple alpha.3 publication state differs from its status")
    if status == APPLE_STATUS_VERIFIED:
        _validate_publication(
            receipt["publication"],
            identity=identity,
            distribution=distribution,
            label=label,
        )
    if key == APPLE_ALPHA2_R1_PUBLICATION_KEY and not publication_values_equal(
        receipt["publication"], frozen_alpha2_r1_publication()
    ):
        _fail(
            "historical Apple alpha.2 publication facts differ from the frozen receipt"
        )


def validate_apple_publications(manifest: dict[str, object]) -> None:
    """Validate optional versioned Apple publication receipts."""

    if not isinstance(manifest, dict):
        _fail("results manifest must be a JSON object")
    publications_value = manifest.get("release_publications")
    if publications_value is None:
        return
    publications = _object(publications_value, "release_publications")
    unknown = sorted(set(publications) - APPLE_PUBLICATION_KEYS)
    if unknown:
        _fail(f"release_publications has unknown Apple entries: {unknown!r}")
    for key in sorted(APPLE_PUBLICATION_KEYS):
        if key in publications:
            _validate_receipt(publications[key], key=key)


def _publication_entries(manifest: dict[str, object]) -> dict[str, object]:
    publications = manifest.get("release_publications")
    if publications is None:
        return {}
    return _object(publications, "release_publications")


def validate_apple_publication_transition(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    """Validate monotonic Apple receipt evolution without mutating inputs."""

    validate_apple_publications(previous)
    validate_apple_publications(current)
    previous_publications = _publication_entries(previous)
    current_publications = _publication_entries(current)

    if APPLE_ALPHA2_R1_PUBLICATION_KEY in previous_publications:
        if APPLE_ALPHA2_R1_PUBLICATION_KEY not in current_publications:
            _fail("Apple alpha.2 publication receipt cannot be removed")
        if not publication_values_equal(
            previous_publications[APPLE_ALPHA2_R1_PUBLICATION_KEY],
            current_publications[APPLE_ALPHA2_R1_PUBLICATION_KEY],
        ):
            _fail("Apple alpha.2 publication receipt cannot change")

    if APPLE_ALPHA3_R1_PUBLICATION_KEY not in previous_publications:
        return
    if APPLE_ALPHA3_R1_PUBLICATION_KEY not in current_publications:
        _fail("Apple alpha.3 publication receipt cannot be removed")
    previous_alpha3 = _object(
        previous_publications[APPLE_ALPHA3_R1_PUBLICATION_KEY],
        "previous Apple alpha.3 publication receipt",
    )
    current_alpha3 = _object(
        current_publications[APPLE_ALPHA3_R1_PUBLICATION_KEY],
        "current Apple alpha.3 publication receipt",
    )
    previous_status = previous_alpha3["status"]
    current_status = current_alpha3["status"]
    if previous_status == APPLE_STATUS_VERIFIED:
        if not publication_values_equal(previous_alpha3, current_alpha3):
            _fail("verified Apple alpha.3 publication receipt cannot change")
        return
    if current_status == APPLE_STATUS_PENDING:
        if not publication_values_equal(previous_alpha3, current_alpha3):
            _fail(
                "pending Apple alpha.3 publication receipt may only remain "
                "unchanged or advance to verified"
            )
        return

    for field in ("boundary", "identity", "kind", "schema_version"):
        if not publication_values_equal(
            previous_alpha3[field], current_alpha3[field]
        ):
            _fail(
                "Apple alpha.3 pending-to-verified transition changed "
                f"the recorded {field}"
            )
    previous_distribution = _object(
        previous_alpha3["distribution"],
        "previous Apple alpha.3 distribution",
    )
    current_distribution = _object(
        current_alpha3["distribution"],
        "current Apple alpha.3 distribution",
    )
    candidate_fields = (
        set(previous_distribution) - _PROMOTION_ONLY_DISTRIBUTION_FIELDS
    )
    for field in sorted(candidate_fields):
        if not publication_values_equal(
            previous_distribution[field], current_distribution[field]
        ):
            _fail(
                "Apple alpha.3 pending-to-verified transition changed "
                f"signed candidate fact {field}"
            )
