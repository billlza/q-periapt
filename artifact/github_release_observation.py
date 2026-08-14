#!/usr/bin/env python3
"""Pure, domain-neutral parsing for one immutable GitHub release observation.

The callers own subprocess execution, private raw retention, path policy, and
domain receipt construction.  This module accepts only already-bounded bytes
and turns GitHub's repository, release, and release-attestation JSON into a
small canonical observation after exact policy checks.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Never

from evidence_io import EvidenceIOError, parse_strict_json_bytes


RELEASE_VIEW_FIELDS = (
    "databaseId",
    "isDraft",
    "isImmutable",
    "isPrerelease",
    "publishedAt",
    "tagName",
    "targetCommitish",
    "url",
    "assets",
)
RELEASE_VIEW_KEYS = frozenset(RELEASE_VIEW_FIELDS)
REPOSITORY_VIEW_FIELDS = ("nameWithOwner", "url", "visibility")
REPOSITORY_VIEW_KEYS = frozenset(REPOSITORY_VIEW_FIELDS)
ASSET_VIEW_KEYS = frozenset(
    {
        "apiUrl",
        "contentType",
        "createdAt",
        "digest",
        "downloadCount",
        "id",
        "label",
        "name",
        "size",
        "state",
        "updatedAt",
        "url",
    }
)
VERIFICATION_RESULT_MEDIA_TYPE = (
    "application/vnd.dev.sigstore.verificationresult+json;version=0.1"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RELEASE_PREDICATE_TYPE = "https://in-toto.io/attestation/release/v0.2"
RELEASE_CERTIFICATE_SAN = "https://dotcom.releases.github.com"
RELEASE_CERTIFICATE_ISSUER = "CN=Fulcio Intermediate l1,O=GitHub\\, Inc."
TIMESTAMP_AUTHORITY_TYPE = "TimestampAuthority"
TIMESTAMP_AUTHORITY_URI = "timestamp.githubapp.com"
MAX_RELEASE_ID = (1 << 63) - 1

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
SAFE_NODE_ID = re.compile(r"^[0-9A-Za-z_-]+$")
SAFE_ASSET_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")


class GitHubReleaseObservationError(ValueError):
    """GitHub release JSON violates an exact immutable-release policy."""


@dataclasses.dataclass(frozen=True, slots=True)
class RepositoryPolicy:
    repository: str
    repository_url: str


@dataclasses.dataclass(frozen=True, slots=True)
class ReleasePolicy:
    repository: str
    repository_url: str
    release_url: str
    download_prefix: str
    api_asset_prefix: str
    tag_subject_uri: str
    tag: str
    tag_commit: str
    tag_object: str | None
    asset_names: tuple[str, ...]
    expected_release_id: int | None = None
    expected_sha256: Mapping[str, str] | None = None
    expected_content_types: Mapping[str, str] | None = None
    require_asset_order: bool = True


@dataclasses.dataclass(frozen=True, slots=True)
class RepositoryView:
    canonical: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseView:
    release_id: int
    published_at: str
    assets: tuple[dict[str, object], ...]
    canonical: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseVerification:
    subjects: tuple[dict[str, object], ...]
    verification_record_sha256: str
    verified_at: str

    def projection(self, *, include_verified_at: bool) -> dict[str, object]:
        """Return the shared release-attestation projection."""

        projection: dict[str, object] = {
            "certificate_san": RELEASE_CERTIFICATE_SAN,
            "predicate_type": RELEASE_PREDICATE_TYPE,
            "subjects": list(self.subjects),
            "verification_record_sha256": self.verification_record_sha256,
            "verified": True,
        }
        if include_verified_at:
            projection["verified_at"] = self.verified_at
        return projection

    def timestamp_authority(self) -> dict[str, object]:
        """Return the timestamp-authority projection used by Apple receipts."""

        return {
            "timestamp": self.verified_at,
            "type": TIMESTAMP_AUTHORITY_TYPE,
            "uri": TIMESTAMP_AUTHORITY_URI,
        }


def _fail(message: str) -> Never:
    raise GitHubReleaseObservationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be a JSON object with string keys",
    )
    return value


def _exact_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    _require(
        actual == expected,
        f"{label} keys differ: missing={sorted(expected - actual)!r} "
        f"extra={sorted(actual - expected)!r}",
    )


def canonical_json(value: object) -> bytes:
    """Return the unique compact ASCII JSON encoding used for record hashes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise GitHubReleaseObservationError(
            "GitHub release verification result is not canonical JSON"
        ) from exc


def _parse_strict_json(data: bytes, label: str) -> object:
    try:
        return parse_strict_json_bytes(data, label=label)
    except EvidenceIOError as exc:
        raise GitHubReleaseObservationError(
            f"{label} is not strict JSON"
        ) from exc


def _sha1(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_40.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-1",
    )
    return value


def _sha256(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_64.fullmatch(value) is not None,
        f"{label} must be a lowercase SHA-256",
    )
    return value


def _positive_integer(value: object, label: str) -> int:
    _require(
        type(value) is int and 0 < value <= MAX_RELEASE_ID,
        f"{label} must be a bounded positive integer",
    )
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    _require(
        type(value) is int and 0 <= value <= MAX_RELEASE_ID,
        f"{label} must be a bounded nonnegative integer",
    )
    return value


def parse_utc_timestamp(value: object, label: str) -> dt.datetime:
    """Parse the exact second-resolution RFC3339 UTC form emitted by GitHub."""

    _require(isinstance(value, str), f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise GitHubReleaseObservationError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _validate_policy(policy: ReleasePolicy) -> None:
    _require(bool(policy.repository), "GitHub release repository is empty")
    _require(
        policy.repository_url == f"https://github.com/{policy.repository}",
        "GitHub release repository URL differs",
    )
    _require(
        policy.release_url
        == f"{policy.repository_url}/releases/tag/{policy.tag}",
        "GitHub release URL policy differs",
    )
    _require(
        policy.download_prefix
        == f"{policy.repository_url}/releases/download/",
        "GitHub release download policy differs",
    )
    _require(
        policy.api_asset_prefix
        == f"https://api.github.com/repos/{policy.repository}/releases/assets/",
        "GitHub release asset API policy differs",
    )
    _require(
        policy.tag_subject_uri == f"pkg:github/{policy.repository}@{policy.tag}",
        "GitHub release tag subject policy differs",
    )
    _sha1(policy.tag_commit, "GitHub release tag commit policy")
    if policy.tag_object is not None:
        _sha1(policy.tag_object, "GitHub release tag object policy")
        _require(
            policy.tag_object != policy.tag_commit,
            "GitHub release tag policy is not annotated",
        )
    _require(
        len(policy.asset_names) > 0
        and len(set(policy.asset_names)) == len(policy.asset_names)
        and all(SAFE_ASSET_NAME.fullmatch(name) is not None for name in policy.asset_names),
        "GitHub release asset-name policy is invalid",
    )
    expected_names = frozenset(policy.asset_names)
    if policy.expected_sha256 is not None:
        _require(
            frozenset(policy.expected_sha256) == expected_names,
            "GitHub release expected-digest policy differs",
        )
        for name in policy.asset_names:
            _sha256(
                policy.expected_sha256[name],
                f"GitHub release expected digest for {name}",
            )
    if policy.expected_content_types is not None:
        _require(
            frozenset(policy.expected_content_types) == expected_names,
            "GitHub release content-type policy differs",
        )
        for name in policy.asset_names:
            content_type = policy.expected_content_types[name]
            _require(
                isinstance(content_type, str)
                and content_type.isascii()
                and 0 < len(content_type) <= 256,
                f"GitHub release content-type policy is invalid for {name}",
            )
    if policy.expected_release_id is not None:
        _positive_integer(
            policy.expected_release_id, "GitHub expected release ID policy"
        )


def parse_repository_view(
    data: bytes,
    *,
    policy: RepositoryPolicy,
    label: str = "GitHub repository visibility view",
) -> RepositoryView:
    """Parse one exact PUBLIC repository view."""

    value = _parse_strict_json(data, label)
    view = _object(value, label)
    _exact_keys(view, REPOSITORY_VIEW_KEYS, label)
    _require(
        view["nameWithOwner"] == policy.repository
        and view["url"] == policy.repository_url,
        f"{label} identity differs",
    )
    _require(view["visibility"] == "PUBLIC", f"{label} is not PUBLIC")
    return RepositoryView(canonical=canonical_json(view))


def parse_release_view(
    data: bytes,
    *,
    policy: ReleasePolicy,
    label: str = "GitHub release view",
) -> ReleaseView:
    """Parse one exact immutable prerelease view and canonical asset projection."""

    _validate_policy(policy)
    value = _parse_strict_json(data, label)
    view = _object(value, label)
    _exact_keys(view, RELEASE_VIEW_KEYS, label)
    release_id = _positive_integer(view["databaseId"], f"{label} release ID")
    if policy.expected_release_id is not None:
        _require(
            release_id == policy.expected_release_id,
            f"{label} release ID differs",
        )
    _require(
        view["isDraft"] is False
        and view["isImmutable"] is True
        and view["isPrerelease"] is True,
        f"{label} publication state differs",
    )
    _require(view["tagName"] == policy.tag, f"{label} tag differs")
    _require(view["url"] == policy.release_url, f"{label} URL differs")
    _require(
        view["targetCommitish"] in {"main", policy.tag_commit},
        f"{label} target differs",
    )
    published_at = view["publishedAt"]
    published_time = parse_utc_timestamp(published_at, f"{label} publishedAt")
    assets_value = view["assets"]
    _require(
        isinstance(assets_value, list)
        and len(assets_value) == len(policy.asset_names),
        f"{label} asset count differs",
    )

    parsed_by_name: dict[str, dict[str, object]] = {}
    actual_order: list[str] = []
    expected_names = frozenset(policy.asset_names)
    for raw_asset in assets_value:
        asset = _object(raw_asset, f"{label} asset")
        _exact_keys(asset, ASSET_VIEW_KEYS, f"{label} asset")
        name = asset["name"]
        _require(
            isinstance(name, str)
            and name in expected_names
            and name not in parsed_by_name,
            f"{label} asset name/set differs",
        )
        actual_order.append(name)
        size = _positive_integer(asset["size"], f"{label} asset size for {name}")
        digest_value = asset["digest"]
        _require(
            isinstance(digest_value, str) and digest_value.startswith("sha256:"),
            f"{label} asset digest differs for {name}",
        )
        digest = _sha256(
            digest_value.removeprefix("sha256:"),
            f"{label} asset digest for {name}",
        )
        if policy.expected_sha256 is not None:
            _require(
                digest == policy.expected_sha256[name],
                f"{label} digest differs for {name}",
            )
        _require(asset["state"] == "uploaded", f"{label} asset state differs")
        content_type = asset["contentType"]
        _require(
            isinstance(content_type, str)
            and content_type.isascii()
            and 0 < len(content_type) <= 256,
            f"{label} asset content type is malformed for {name}",
        )
        if policy.expected_content_types is not None:
            _require(
                content_type == policy.expected_content_types[name],
                f"{label} asset content type differs for {name}",
            )
        _require(asset["label"] == "", f"{label} asset label differs")
        _require(
            asset["url"]
            == f"{policy.download_prefix}{policy.tag}/{name}",
            f"{label} asset URL differs for {name}",
        )
        api_url = asset["apiUrl"]
        _require(
            isinstance(api_url, str)
            and re.fullmatch(
                re.escape(policy.api_asset_prefix) + r"[1-9][0-9]*", api_url
            )
            is not None,
            f"{label} asset API URL differs for {name}",
        )
        node_id = asset["id"]
        _require(
            isinstance(node_id, str)
            and len(node_id) <= 256
            and SAFE_NODE_ID.fullmatch(node_id) is not None,
            f"{label} asset node ID is malformed for {name}",
        )
        created_at = parse_utc_timestamp(
            asset["createdAt"], f"{label} asset createdAt for {name}"
        )
        updated_at = parse_utc_timestamp(
            asset["updatedAt"], f"{label} asset updatedAt for {name}"
        )
        _require(
            created_at <= updated_at <= published_time,
            f"{label} asset timestamps are out of order for {name}",
        )
        _nonnegative_integer(
            asset["downloadCount"], f"{label} asset download count for {name}"
        )
        parsed_by_name[name] = {"bytes": size, "name": name, "sha256": digest}

    _require(
        frozenset(parsed_by_name) == expected_names,
        f"{label} asset set differs",
    )
    if policy.require_asset_order:
        _require(
            tuple(actual_order) == policy.asset_names,
            f"{label} asset order differs",
        )
    assets = tuple(parsed_by_name[name] for name in policy.asset_names)
    stable = {
        "assets": list(assets),
        "draft": False,
        "immutable": True,
        "prerelease": True,
        "published_at": published_at,
        "release_id": release_id,
        "tag": policy.tag,
    }
    return ReleaseView(
        release_id=release_id,
        published_at=published_at,
        assets=assets,
        canonical=canonical_json(stable),
    )


def expected_subjects(policy: ReleasePolicy) -> list[dict[str, object]]:
    """Return the exact release-attestation subject order for a policy."""

    _validate_policy(policy)
    _require(
        policy.expected_sha256 is not None,
        "GitHub release attestation policy lacks expected asset digests",
    )
    _require(
        policy.tag_object is not None,
        "GitHub release attestation policy lacks an annotated tag object",
    )
    return [
        {"digest": {"sha1": policy.tag_object}, "uri": policy.tag_subject_uri},
        *[
            {
                "digest": {"sha256": policy.expected_sha256[name]},
                "name": name,
            }
            for name in policy.asset_names
        ],
    ]


def parse_release_verification(
    data: bytes,
    *,
    policy: ReleasePolicy,
    release_id: int,
    published_at: str,
    label: str = "GitHub release verification",
) -> ReleaseVerification:
    """Parse one exact GitHub release verification result and its subjects."""

    _validate_policy(policy)
    release_id = _positive_integer(release_id, f"{label} release ID")
    if policy.expected_release_id is not None:
        _require(
            release_id == policy.expected_release_id,
            f"{label} release ID differs",
        )
    publication_time = parse_utc_timestamp(published_at, f"{label} publishedAt")
    value = _parse_strict_json(data, label)
    envelope = _object(value, label)
    _exact_keys(
        envelope,
        frozenset({"attestation", "verificationResult"}),
        label,
    )
    _require(
        isinstance(envelope["attestation"], dict),
        f"{label} attestation bundle is not an object",
    )
    result = _object(envelope["verificationResult"], f"{label} result")
    _exact_keys(
        result,
        frozenset(
            {
                "mediaType",
                "signature",
                "statement",
                "verifiedIdentity",
                "verifiedTimestamps",
            }
        ),
        f"{label} result",
    )
    _require(
        result["mediaType"] == VERIFICATION_RESULT_MEDIA_TYPE,
        f"{label} media type differs",
    )
    signature = _object(result["signature"], f"{label} signature")
    _exact_keys(signature, frozenset({"certificate"}), f"{label} signature")
    certificate = _object(signature["certificate"], f"{label} certificate")
    _exact_keys(
        certificate,
        frozenset({"certificateIssuer", "subjectAlternativeName"}),
        f"{label} certificate",
    )
    _require(
        certificate
        == {
            "certificateIssuer": RELEASE_CERTIFICATE_ISSUER,
            "subjectAlternativeName": RELEASE_CERTIFICATE_SAN,
        },
        f"{label} certificate identity differs",
    )
    _require(
        result["verifiedIdentity"]
        == {
            "issuer": {"issuer": "", "regexp": ".*"},
            "subjectAlternativeName": {
                "regexp": r"^https://dotcom\.releases\.github\.com$",
                "subjectAlternativeName": "",
            },
        },
        f"{label} verified identity differs",
    )
    timestamps = result["verifiedTimestamps"]
    _require(
        isinstance(timestamps, list) and len(timestamps) == 1,
        f"{label} verified timestamp count differs",
    )
    timestamp = _object(timestamps[0], f"{label} verified timestamp")
    _exact_keys(
        timestamp,
        frozenset({"timestamp", "type", "uri"}),
        f"{label} verified timestamp",
    )
    _require(
        timestamp["type"] == TIMESTAMP_AUTHORITY_TYPE
        and timestamp["uri"] == TIMESTAMP_AUTHORITY_URI,
        f"{label} timestamp authority differs",
    )
    timestamp_time = parse_utc_timestamp(
        timestamp["timestamp"], f"{label} attestation timestamp"
    )
    _require(
        publication_time <= timestamp_time,
        f"{label} attestation predates release publication",
    )

    statement = _object(result["statement"], f"{label} statement")
    _exact_keys(
        statement,
        frozenset({"_type", "predicate", "predicateType", "subject"}),
        f"{label} statement",
    )
    _require(statement["_type"] == STATEMENT_TYPE, f"{label} statement type differs")
    _require(
        statement["predicateType"] == RELEASE_PREDICATE_TYPE,
        f"{label} predicate type differs",
    )
    subjects = expected_subjects(policy)
    _require(statement["subject"] == subjects, f"{label} subjects differ")
    predicate = _object(statement["predicate"], f"{label} predicate")
    _exact_keys(
        predicate,
        frozenset(
            {
                "databaseId",
                "ownerId",
                "packageId",
                "purl",
                "repository",
                "repositoryId",
                "tag",
            }
        ),
        f"{label} predicate",
    )
    repository_id = predicate["repositoryId"]
    owner_id = predicate["ownerId"]
    _require(
        isinstance(repository_id, str)
        and POSITIVE_DECIMAL.fullmatch(repository_id) is not None
        and predicate["packageId"] == repository_id
        and isinstance(owner_id, str)
        and POSITIVE_DECIMAL.fullmatch(owner_id) is not None,
        f"{label} repository identity is malformed",
    )
    _require(
        predicate["databaseId"] == str(release_id)
        and predicate["purl"] == policy.tag_subject_uri
        and predicate["repository"] == policy.repository
        and predicate["tag"] == policy.tag,
        f"{label} predicate identity differs",
    )
    return ReleaseVerification(
        subjects=tuple(subjects),
        verification_record_sha256=hashlib.sha256(canonical_json(result)).hexdigest(),
        verified_at=timestamp["timestamp"],
    )
