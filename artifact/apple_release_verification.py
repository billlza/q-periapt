#!/usr/bin/env python3
"""Collect and sanitize one GitHub Apple release-verification transaction.

This I/O adapter is deliberately independent from the pure Apple publication
receipt contract.  It invokes fixed ``git`` and ``gh`` observations through the
repository's bounded subprocess runner, retains private raw JSON, and publishes
only a small PII-safe projection after all local and remote samples agree.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Never

from bounded_process import BoundedProcessError, BoundedResult, capture_stdout
from evidence_io import (
    EvidenceIOError,
    parse_strict_json_bytes,
    read_regular_snapshot,
)


REPOSITORY = "billlza/q-periapt"
GH_REPOSITORY_ARGUMENT = f"github.com/{REPOSITORY}"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
API_ASSET_PREFIX = f"https://api.github.com/repos/{REPOSITORY}/releases/assets/"
RELEASE_URL_PREFIX = f"{REPOSITORY_URL}/releases/tag/"
RELEASE_DOWNLOAD_PREFIX = f"{REPOSITORY_URL}/releases/download/"
TAG_SUBJECT_PREFIX = f"pkg:github/{REPOSITORY}@"

COMPLETION_LEDGER_KIND = "qperiapt.apple_static_xcframework_release_completion"
HISTORICAL_EXPECTATION_KIND = "qperiapt.apple_public_asset_expectation"
PROJECTION_KIND = "qperiapt.apple_github_release_verification"
PROJECTION_SCHEMA_VERSION = 1
PROJECTION_NAME = "apple-github-release-verification.json"
RAW_VIEW_BEFORE_NAME = "release-view-before.json"
RAW_VERIFY_NAME = "release-verify.json"
RAW_VIEW_AFTER_NAME = "release-view-after.json"
RAW_REPOSITORY_BEFORE_NAME = "repository-view-before.json"
RAW_REPOSITORY_AFTER_NAME = "repository-view-after.json"
RAW_NAMES = frozenset(
    {
        RAW_REPOSITORY_AFTER_NAME,
        RAW_REPOSITORY_BEFORE_NAME,
        RAW_VIEW_BEFORE_NAME,
        RAW_VERIFY_NAME,
        RAW_VIEW_AFTER_NAME,
    }
)

XCFRAMEWORK_ZIP_NAME = "CQPeriapt.xcframework.zip"
APPLE_DISTRIBUTION_NAME = "APPLE_DISTRIBUTION.json"
MANIFEST_NAME = "MANIFEST.json"
SHA256SUMS_NAME = "SHA256SUMS"
ASSET_NAMES = (
    APPLE_DISTRIBUTION_NAME,
    XCFRAMEWORK_ZIP_NAME,
    MANIFEST_NAME,
    SHA256SUMS_NAME,
)
ASSET_CONTENT_TYPES = {
    APPLE_DISTRIBUTION_NAME: "application/json",
    XCFRAMEWORK_ZIP_NAME: "application/zip",
    MANIFEST_NAME: "application/json",
    SHA256SUMS_NAME: "application/octet-stream",
}

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

MAX_LEDGER_BYTES = 1024 * 1024
MAX_RELEASE_VIEW_BYTES = 4 * 1024 * 1024
MAX_RELEASE_VERIFY_BYTES = 16 * 1024 * 1024
MAX_REPOSITORY_VIEW_BYTES = 1024 * 1024
MAX_RELEASE_ID = (1 << 63) - 1
GH_TIMEOUT_SECONDS = 120
GIT_TIMEOUT_SECONDS = 30

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
PRODUCT_VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
REVISION = re.compile(r"^r[1-9][0-9]*$")
SAFE_TAG = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
SAFE_NODE_ID = re.compile(r"^[0-9A-Za-z_-]+$")
SAFE_DIRECTORY_LEAF = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")

DANGEROUS_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)


class AppleReleaseVerificationError(ValueError):
    """One local or GitHub release observation violates the I/O contract."""


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseExpectation:
    product_version: str
    revision: str
    tag: str
    tag_commit: str
    asset_sha256: Mapping[str, str]

    @property
    def release_url(self) -> str:
        return f"{RELEASE_URL_PREFIX}{self.tag}"


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseView:
    published_at: str
    assets: tuple[dict[str, object], ...]
    canonical: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class RepositoryView:
    canonical: bytes


CommandRunner = Callable[..., BoundedResult]
Clock = Callable[[], dt.datetime]


def _fail(message: str) -> Never:
    raise AppleReleaseVerificationError(message)


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


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AppleReleaseVerificationError(
            "GitHub release verification result is not canonical JSON"
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


def _timestamp(value: object, label: str) -> dt.datetime:
    _require(isinstance(value, str), f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise AppleReleaseVerificationError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    return parsed.replace(tzinfo=dt.UTC)


def _system_clock() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _observation_timestamp(clock: Clock, *, not_before: str) -> str:
    observed = clock()
    _require(
        isinstance(observed, dt.datetime)
        and observed.tzinfo is not None
        and observed.utcoffset() is not None,
        "Apple release observation clock must return a timezone-aware datetime",
    )
    observed_utc = observed.astimezone(dt.UTC).replace(microsecond=0)
    _require(
        _timestamp(not_before, "GitHub Apple attestation timestamp")
        <= observed_utc,
        "Apple release observation predates attestation verification",
    )
    return observed_utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError("private Apple release file metadata differs")


def _read_private_bytes(
    path: pathlib.Path, *, maximum: int, label: str
) -> bytes:
    try:
        return read_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
            validate_metadata=_private_file_metadata,
        ).data
    except EvidenceIOError as exc:
        raise AppleReleaseVerificationError(f"cannot safely read {label}") from exc


def _parse_strict_json(data: bytes, label: str) -> object:
    try:
        return parse_strict_json_bytes(data, label=label)
    except EvidenceIOError as exc:
        raise AppleReleaseVerificationError(f"{label} is not strict JSON") from exc


def _directory_fd(
    path: pathlib.Path,
    *,
    label: str,
    required_mode: int | None,
) -> int:
    _require(path.is_absolute(), f"{label} must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AppleReleaseVerificationError(f"cannot inspect {label}") from exc
    valid = (
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == os.geteuid()
    )
    if required_mode is not None:
        valid = valid and stat.S_IMODE(metadata.st_mode) == required_mode
    _require(valid, f"{label} is not an owned non-symlink directory")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AppleReleaseVerificationError(f"cannot open {label}") from exc
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.geteuid()
        or opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
        or (
            required_mode is not None
            and stat.S_IMODE(opened.st_mode) != required_mode
        )
    ):
        os.close(descriptor)
        _fail(f"{label} identity changed")
    return descriptor


def _require_absent_at(directory_fd: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AppleReleaseVerificationError(f"cannot inspect {label}") from exc
    _fail(f"{label} already exists")


def _validate_projection_path(path: pathlib.Path) -> None:
    _require(path.is_absolute(), "Apple release projection must be absolute")
    _require(path.name == PROJECTION_NAME, "Apple release projection leaf differs")
    parent_fd = _directory_fd(
        path.parent,
        label="Apple release projection parent",
        required_mode=0o700,
    )
    try:
        _require_absent_at(parent_fd, PROJECTION_NAME, "Apple release projection")
    finally:
        os.close(parent_fd)


def _paths_overlap(left: pathlib.Path, right: pathlib.Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_io_path_disjointness(
    asset_ledger: pathlib.Path,
    raw_directory: pathlib.Path,
    projection_output: pathlib.Path,
) -> None:
    """Keep trusted input, private raw, and sanitized output in separate trees."""

    for path, label in (
        (asset_ledger, "Apple release asset ledger"),
        (raw_directory, "Apple release raw directory"),
        (projection_output, "Apple release projection"),
    ):
        _require(path.is_absolute(), f"{label} must be absolute")
    try:
        ledger_parent = asset_ledger.resolve(strict=True).parent
        raw_target = raw_directory.parent.resolve(strict=True) / raw_directory.name
        projection_parent = projection_output.parent.resolve(strict=True)
    except OSError as exc:
        raise AppleReleaseVerificationError(
            "cannot resolve Apple release I/O paths"
        ) from exc
    compartments = (ledger_parent, raw_target, projection_parent)
    for index, left in enumerate(compartments):
        for right in compartments[index + 1 :]:
            _require(
                not _paths_overlap(left, right),
                "Apple release ledger, raw, and projection paths must be disjoint",
            )


def _create_raw_directory(path: pathlib.Path) -> int:
    _require(path.is_absolute(), "Apple release raw directory must be absolute")
    _require(
        SAFE_DIRECTORY_LEAF.fullmatch(path.name) is not None,
        "Apple release raw directory leaf is unsafe",
    )
    parent_fd = _directory_fd(
        path.parent,
        label="Apple release raw parent",
        required_mode=None,
    )
    try:
        _require_absent_at(parent_fd, path.name, "Apple release raw directory")
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise AppleReleaseVerificationError(
                "cannot create Apple release raw directory"
            ) from exc
    finally:
        os.close(parent_fd)
    return _directory_fd(
        path,
        label="Apple release raw directory",
        required_mode=0o700,
    )


def _write_private_bytes_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    label: str,
) -> None:
    _require(SAFE_DIRECTORY_LEAF.fullmatch(name) is not None, f"{label} leaf is unsafe")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            _require(written > 0, f"{label} write made no progress")
            offset += written
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            f"{label} private file identity differs",
        )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(directory_fd)
    except FileExistsError as exc:
        raise AppleReleaseVerificationError(f"{label} already exists") from exc
    except OSError as exc:
        raise AppleReleaseVerificationError(f"cannot write {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_projection(path: pathlib.Path, projection: object) -> str:
    _validate_projection_path(path)
    payload = (
        json.dumps(projection, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    ).encode("ascii")
    parent_fd = _directory_fd(
        path.parent,
        label="Apple release projection parent",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            parent_fd,
            PROJECTION_NAME,
            payload,
            label="Apple release projection",
        )
    finally:
        os.close(parent_fd)
    return hashlib.sha256(payload).hexdigest()


def load_release_expectation(path: pathlib.Path) -> ReleaseExpectation:
    """Load one private completion or historical expected-assets ledger."""

    _require(path.is_absolute(), "Apple release asset ledger must be absolute")
    value = _parse_strict_json(
        _read_private_bytes(
            path,
            maximum=MAX_LEDGER_BYTES,
            label="Apple release asset ledger",
        ),
        "Apple release asset ledger",
    )
    ledger = _object(value, "Apple release asset ledger")
    _exact_keys(
        ledger,
        frozenset(
            {
                "kind",
                "public_assets_sha256",
                "release_identity",
                "schema_version",
                "source_commit",
            }
        ),
        "Apple release asset ledger",
    )
    expected_schema = {
        COMPLETION_LEDGER_KIND: 2,
        HISTORICAL_EXPECTATION_KIND: 1,
    }.get(ledger["kind"])
    _require(
        expected_schema is not None
        and type(ledger["schema_version"]) is int
        and ledger["schema_version"] == expected_schema,
        "Apple release asset ledger discriminant differs",
    )
    tag_commit = _sha1(ledger["source_commit"], "Apple release source commit")
    identity = _object(ledger["release_identity"], "Apple release identity")
    _exact_keys(
        identity,
        frozenset({"product_version", "revision", "tag"}),
        "Apple release identity",
    )
    product_version = identity["product_version"]
    revision = identity["revision"]
    tag = identity["tag"]
    _require(
        isinstance(product_version, str)
        and PRODUCT_VERSION.fullmatch(product_version) is not None,
        "Apple release product version is invalid",
    )
    _require(
        isinstance(revision, str) and REVISION.fullmatch(revision) is not None,
        "Apple release revision is invalid",
    )
    _require(
        isinstance(tag, str)
        and SAFE_TAG.fullmatch(tag) is not None
        and tag == f"v{product_version}-{revision}",
        "Apple release tag differs from its identity",
    )
    hashes = _object(
        ledger["public_assets_sha256"], "Apple release expected asset hashes"
    )
    _exact_keys(hashes, frozenset(ASSET_NAMES), "Apple release expected asset hashes")
    asset_hashes = {
        name: _sha256(hashes[name], f"Apple release expected digest for {name}")
        for name in ASSET_NAMES
    }
    return ReleaseExpectation(
        product_version=product_version,
        revision=revision,
        tag=tag,
        tag_commit=tag_commit,
        asset_sha256=asset_hashes,
    )


def _release_id(value: str) -> int:
    maximum = str(MAX_RELEASE_ID)
    _require(
        isinstance(value, str)
        and len(value) <= len(maximum)
        and POSITIVE_DECIMAL.fullmatch(value) is not None
        and (len(value) < len(maximum) or value <= maximum),
        "expected GitHub release ID must be a bounded positive decimal integer",
    )
    release_id = int(value)
    return release_id


def _tool(name: str) -> str:
    located = shutil.which(name)
    _require(located is not None, f"required Apple release tool is unavailable: {name}")
    try:
        resolved = pathlib.Path(located).resolve(strict=True)
    except OSError as exc:
        raise AppleReleaseVerificationError(
            f"cannot resolve required Apple release tool: {name}"
        ) from exc
    _require(
        resolved.is_file() and os.access(resolved, os.X_OK),
        f"required Apple release tool is not executable: {name}",
    )
    return str(resolved)


def _process_environment(source: Mapping[str, str]) -> dict[str, str]:
    overridden = sorted(DANGEROUS_GIT_ENVIRONMENT.intersection(source))
    _require(
        not overridden,
        "Apple release verification rejects Git environment overrides",
    )
    environment = dict(source)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LANG": "C",
            "LC_ALL": "C",
        }
    )
    environment.pop("GH_HOST", None)
    environment.pop("GH_REPO", None)
    return environment


def _capture_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: CommandRunner,
) -> bytes:
    try:
        result = runner(
            argv,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            stderr=subprocess.DEVNULL,
            environment=environment,
        )
    except BoundedProcessError as exc:
        raise AppleReleaseVerificationError(f"{label} failed safely") from exc
    _require(result.returncode == 0, f"{label} was rejected")
    _require(result.stdout, f"{label} returned empty output")
    return result.stdout


def _git_base(git: str) -> list[str]:
    root = pathlib.Path(__file__).resolve().parent.parent
    return [
        git,
        "-C",
        str(root),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
    ]


def _git_line(
    git: str,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    label: str,
    runner: CommandRunner,
) -> str:
    raw = _capture_command(
        [*_git_base(git), *arguments],
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        maximum_bytes=1024,
        environment=environment,
        label=label,
        runner=runner,
    )
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AppleReleaseVerificationError(f"{label} output is not ASCII") from exc
    _require(value.endswith("\n") and value.count("\n") == 1, f"{label} output differs")
    return value[:-1]


def _verify_local_tag(
    git: str,
    expectation: ReleaseExpectation,
    expected_tag_object: str,
    *,
    environment: Mapping[str, str],
    runner: CommandRunner,
) -> tuple[str, str]:
    reference = f"refs/tags/{expectation.tag}"
    tag_type = _git_line(
        git,
        ["cat-file", "-t", reference],
        environment=environment,
        label="Apple release tag type observation",
        runner=runner,
    )
    _require(tag_type == "tag", "Apple release tag is not annotated")
    tag_object = _git_line(
        git,
        ["rev-parse", "--verify", reference],
        environment=environment,
        label="Apple release tag object observation",
        runner=runner,
    )
    tag_commit = _git_line(
        git,
        ["rev-parse", "--verify", f"{reference}^{{commit}}"],
        environment=environment,
        label="Apple release peeled commit observation",
        runner=runner,
    )
    _require(
        HEX_40.fullmatch(tag_object) is not None
        and tag_object == expected_tag_object,
        "Apple release annotated tag object differs",
    )
    _require(
        HEX_40.fullmatch(tag_commit) is not None
        and tag_commit == expectation.tag_commit,
        "Apple release peeled commit differs",
    )
    return tag_object, tag_commit


def _parse_release_view(
    data: bytes,
    *,
    expectation: ReleaseExpectation,
    release_id: int,
) -> ReleaseView:
    value = _parse_strict_json(data, "GitHub Apple release view")
    view = _object(value, "GitHub Apple release view")
    _exact_keys(view, RELEASE_VIEW_KEYS, "GitHub Apple release view")
    _require(
        type(view["databaseId"]) is int and view["databaseId"] == release_id,
        "GitHub Apple release ID differs",
    )
    _require(
        view["isDraft"] is False
        and view["isImmutable"] is True
        and view["isPrerelease"] is True,
        "GitHub Apple release publication state differs",
    )
    _require(view["tagName"] == expectation.tag, "GitHub Apple release tag differs")
    _require(view["url"] == expectation.release_url, "GitHub Apple release URL differs")
    _require(
        view["targetCommitish"] in {"main", expectation.tag_commit},
        "GitHub Apple release target differs",
    )
    published_at = view["publishedAt"]
    published_time = _timestamp(published_at, "GitHub Apple release publishedAt")
    assets_value = view["assets"]
    _require(
        isinstance(assets_value, list) and len(assets_value) == len(ASSET_NAMES),
        "GitHub Apple release asset count differs",
    )
    assets: list[dict[str, object]] = []
    for index, expected_name in enumerate(ASSET_NAMES):
        asset = _object(assets_value[index], "GitHub Apple release asset")
        _exact_keys(asset, ASSET_VIEW_KEYS, "GitHub Apple release asset")
        _require(asset["name"] == expected_name, "GitHub Apple release asset order differs")
        size = _positive_integer(asset["size"], f"GitHub Apple asset size for {expected_name}")
        expected_digest = expectation.asset_sha256[expected_name]
        _require(
            asset["digest"] == f"sha256:{expected_digest}",
            f"GitHub Apple release digest differs for {expected_name}",
        )
        _require(asset["state"] == "uploaded", "GitHub Apple asset state differs")
        _require(
            asset["contentType"] == ASSET_CONTENT_TYPES[expected_name],
            f"GitHub Apple asset content type differs for {expected_name}",
        )
        _require(asset["label"] == "", "GitHub Apple release asset label differs")
        expected_url = (
            f"{RELEASE_DOWNLOAD_PREFIX}{expectation.tag}/{expected_name}"
        )
        _require(asset["url"] == expected_url, "GitHub Apple asset URL differs")
        api_url = asset["apiUrl"]
        _require(
            isinstance(api_url, str)
            and re.fullmatch(re.escape(API_ASSET_PREFIX) + r"[1-9][0-9]*", api_url)
            is not None,
            "GitHub Apple asset API URL differs",
        )
        node_id = asset["id"]
        _require(
            isinstance(node_id, str)
            and len(node_id) <= 256
            and SAFE_NODE_ID.fullmatch(node_id) is not None,
            "GitHub Apple asset node ID is malformed",
        )
        created_at = _timestamp(
            asset["createdAt"], f"GitHub Apple asset createdAt for {expected_name}"
        )
        updated_at = _timestamp(
            asset["updatedAt"], f"GitHub Apple asset updatedAt for {expected_name}"
        )
        _require(
            created_at <= updated_at <= published_time,
            f"GitHub Apple asset timestamps are out of order for {expected_name}",
        )
        _nonnegative_integer(
            asset["downloadCount"],
            f"GitHub Apple asset download count for {expected_name}",
        )
        assets.append(
            {"bytes": size, "name": expected_name, "sha256": expected_digest}
        )
    return ReleaseView(
        published_at=published_at,
        assets=tuple(assets),
        canonical=_canonical_json(
            {"assets": assets, "published_at": published_at}
        ),
    )


def _parse_repository_view(data: bytes) -> RepositoryView:
    value = _parse_strict_json(data, "GitHub repository visibility view")
    view = _object(value, "GitHub repository visibility view")
    _exact_keys(view, REPOSITORY_VIEW_KEYS, "GitHub repository visibility view")
    _require(
        view["nameWithOwner"] == REPOSITORY
        and view["url"] == REPOSITORY_URL,
        "GitHub repository visibility identity differs",
    )
    _require(
        view["visibility"] == "PUBLIC",
        "GitHub repository visibility is not PUBLIC",
    )
    return RepositoryView(canonical=_canonical_json(view))


def _expected_subjects(
    expectation: ReleaseExpectation, expected_tag_object: str
) -> list[dict[str, object]]:
    return [
        {
            "digest": {"sha1": expected_tag_object},
            "uri": f"{TAG_SUBJECT_PREFIX}{expectation.tag}",
        },
        *[
            {
                "digest": {"sha256": expectation.asset_sha256[name]},
                "name": name,
            }
            for name in ASSET_NAMES
        ],
    ]


def _parse_release_verification(
    data: bytes,
    *,
    expectation: ReleaseExpectation,
    release_id: int,
    expected_tag_object: str,
    published_at: str,
) -> tuple[dict[str, object], dict[str, object]]:
    value = _parse_strict_json(data, "GitHub Apple release verification")
    envelope = _object(value, "GitHub Apple release verification")
    _exact_keys(
        envelope,
        frozenset({"attestation", "verificationResult"}),
        "GitHub Apple release verification",
    )
    _require(
        isinstance(envelope["attestation"], dict),
        "GitHub Apple release attestation bundle is not an object",
    )
    result = _object(
        envelope["verificationResult"], "GitHub Apple verification result"
    )
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
        "GitHub Apple verification result",
    )
    _require(
        result["mediaType"] == VERIFICATION_RESULT_MEDIA_TYPE,
        "GitHub Apple verification media type differs",
    )
    signature = _object(result["signature"], "GitHub Apple release signature")
    _exact_keys(signature, frozenset({"certificate"}), "GitHub Apple release signature")
    certificate = _object(
        signature["certificate"], "GitHub Apple release certificate"
    )
    _exact_keys(
        certificate,
        frozenset({"certificateIssuer", "subjectAlternativeName"}),
        "GitHub Apple release certificate",
    )
    _require(
        certificate
        == {
            "certificateIssuer": RELEASE_CERTIFICATE_ISSUER,
            "subjectAlternativeName": RELEASE_CERTIFICATE_SAN,
        },
        "GitHub Apple release certificate identity differs",
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
        "GitHub Apple verified identity differs",
    )
    timestamps = result["verifiedTimestamps"]
    _require(
        isinstance(timestamps, list) and len(timestamps) == 1,
        "GitHub Apple verified timestamp count differs",
    )
    timestamp = _object(timestamps[0], "GitHub Apple verified timestamp")
    _exact_keys(
        timestamp,
        frozenset({"timestamp", "type", "uri"}),
        "GitHub Apple verified timestamp",
    )
    _require(
        timestamp["type"] == TIMESTAMP_AUTHORITY_TYPE
        and timestamp["uri"] == TIMESTAMP_AUTHORITY_URI,
        "GitHub Apple timestamp authority differs",
    )
    timestamp_time = _timestamp(
        timestamp["timestamp"], "GitHub Apple attestation timestamp"
    )
    _require(
        _timestamp(published_at, "GitHub Apple release publishedAt") <= timestamp_time,
        "GitHub Apple attestation predates release publication",
    )

    statement = _object(result["statement"], "GitHub Apple release statement")
    _exact_keys(
        statement,
        frozenset({"_type", "predicate", "predicateType", "subject"}),
        "GitHub Apple release statement",
    )
    _require(statement["_type"] == STATEMENT_TYPE, "GitHub Apple statement type differs")
    _require(
        statement["predicateType"] == RELEASE_PREDICATE_TYPE,
        "GitHub Apple release predicate type differs",
    )
    subjects = _expected_subjects(expectation, expected_tag_object)
    _require(statement["subject"] == subjects, "GitHub Apple release subjects differ")
    predicate = _object(statement["predicate"], "GitHub Apple release predicate")
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
        "GitHub Apple release predicate",
    )
    repository_id = predicate["repositoryId"]
    owner_id = predicate["ownerId"]
    _require(
        isinstance(repository_id, str)
        and POSITIVE_DECIMAL.fullmatch(repository_id) is not None
        and predicate["packageId"] == repository_id
        and isinstance(owner_id, str)
        and POSITIVE_DECIMAL.fullmatch(owner_id) is not None,
        "GitHub Apple release repository identity is malformed",
    )
    purl = f"{TAG_SUBJECT_PREFIX}{expectation.tag}"
    _require(
        predicate["databaseId"] == str(release_id)
        and predicate["purl"] == purl
        and predicate["repository"] == REPOSITORY
        and predicate["tag"] == expectation.tag,
        "GitHub Apple release predicate identity differs",
    )
    verified_at = timestamp["timestamp"]
    attestation_projection = {
        "certificate_san": RELEASE_CERTIFICATE_SAN,
        "predicate_type": RELEASE_PREDICATE_TYPE,
        "subjects": subjects,
        "verification_record_sha256": hashlib.sha256(
            _canonical_json(result)
        ).hexdigest(),
        "verified": True,
        "verified_at": verified_at,
    }
    timestamp_authority = {
        "timestamp": verified_at,
        "type": TIMESTAMP_AUTHORITY_TYPE,
        "uri": TIMESTAMP_AUTHORITY_URI,
    }
    return attestation_projection, timestamp_authority


def _validate_raw_directory(path: pathlib.Path) -> None:
    descriptor = _directory_fd(
        path,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    os.close(descriptor)
    try:
        actual = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise AppleReleaseVerificationError(
            "cannot enumerate Apple release raw directory"
        ) from exc
    _require(actual == RAW_NAMES, "Apple release raw file set differs")


def collect_release_verification(
    asset_ledger: pathlib.Path,
    expected_release_id: str,
    expected_tag_object: str,
    raw_directory: pathlib.Path,
    projection_output: pathlib.Path,
    *,
    runner: CommandRunner = capture_stdout,
    clock: Clock = _system_clock,
    source_environment: Mapping[str, str] | None = None,
    git_tool: str | None = None,
    gh_tool: str | None = None,
) -> tuple[str, ReleaseExpectation, int]:
    """Collect one local/remote transaction and publish its safe projection."""

    expectation = load_release_expectation(asset_ledger)
    release_id = _release_id(expected_release_id)
    tag_object = _sha1(expected_tag_object, "expected Apple release tag object")
    _validate_io_path_disjointness(
        asset_ledger,
        raw_directory,
        projection_output,
    )
    _validate_projection_path(projection_output)
    environment = _process_environment(
        os.environ if source_environment is None else source_environment
    )
    git = _tool("git") if git_tool is None else git_tool
    gh = _tool("gh") if gh_tool is None else gh_tool
    raw_fd = _create_raw_directory(raw_directory)
    os.close(raw_fd)

    local_before = _verify_local_tag(
        git,
        expectation,
        tag_object,
        environment=environment,
        runner=runner,
    )
    repository_arguments = [
        gh,
        "repo",
        "view",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(REPOSITORY_VIEW_FIELDS),
    ]
    view_arguments = [
        gh,
        "release",
        "view",
        expectation.tag,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(RELEASE_VIEW_FIELDS),
    ]
    verify_arguments = [
        gh,
        "release",
        "verify",
        expectation.tag,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--format",
        "json",
    ]
    repository_before_raw = _capture_command(
        repository_arguments,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=environment,
        label="GitHub repository visibility before observation",
        runner=runner,
    )
    raw_fd = _directory_fd(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            raw_fd,
            RAW_REPOSITORY_BEFORE_NAME,
            repository_before_raw,
            label="Apple release raw repository-before",
        )
    finally:
        os.close(raw_fd)
    repository_before = _parse_repository_view(
        _read_private_bytes(
            raw_directory / RAW_REPOSITORY_BEFORE_NAME,
            maximum=MAX_REPOSITORY_VIEW_BYTES,
            label="Apple release raw repository-before",
        )
    )
    view_before_raw = _capture_command(
        view_arguments,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=environment,
        label="GitHub Apple release view-before observation",
        runner=runner,
    )
    raw_fd = _directory_fd(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            raw_fd,
            RAW_VIEW_BEFORE_NAME,
            view_before_raw,
            label="Apple release raw view-before",
        )
    finally:
        os.close(raw_fd)

    verify_raw = _capture_command(
        verify_arguments,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VERIFY_BYTES,
        environment=environment,
        label="GitHub Apple release attestation verification",
        runner=runner,
    )
    raw_fd = _directory_fd(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            raw_fd,
            RAW_VERIFY_NAME,
            verify_raw,
            label="Apple release raw verification",
        )
    finally:
        os.close(raw_fd)

    view_after_raw = _capture_command(
        view_arguments,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=environment,
        label="GitHub Apple release view-after observation",
        runner=runner,
    )
    raw_fd = _directory_fd(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            raw_fd,
            RAW_VIEW_AFTER_NAME,
            view_after_raw,
            label="Apple release raw view-after",
        )
    finally:
        os.close(raw_fd)

    repository_after_raw = _capture_command(
        repository_arguments,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=environment,
        label="GitHub repository visibility after observation",
        runner=runner,
    )
    raw_fd = _directory_fd(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    )
    try:
        _write_private_bytes_at(
            raw_fd,
            RAW_REPOSITORY_AFTER_NAME,
            repository_after_raw,
            label="Apple release raw repository-after",
        )
    finally:
        os.close(raw_fd)

    local_after = _verify_local_tag(
        git,
        expectation,
        tag_object,
        environment=environment,
        runner=runner,
    )
    _require(
        local_after == local_before,
        "Apple release local tag changed during verification",
    )
    _validate_raw_directory(raw_directory)
    repository_after = _parse_repository_view(
        _read_private_bytes(
            raw_directory / RAW_REPOSITORY_AFTER_NAME,
            maximum=MAX_REPOSITORY_VIEW_BYTES,
            label="Apple release raw repository-after",
        )
    )
    _require(
        repository_after.canonical == repository_before.canonical,
        "GitHub repository visibility changed during verification",
    )
    view_before = _parse_release_view(
        _read_private_bytes(
            raw_directory / RAW_VIEW_BEFORE_NAME,
            maximum=MAX_RELEASE_VIEW_BYTES,
            label="Apple release raw view-before",
        ),
        expectation=expectation,
        release_id=release_id,
    )
    view_after = _parse_release_view(
        _read_private_bytes(
            raw_directory / RAW_VIEW_AFTER_NAME,
            maximum=MAX_RELEASE_VIEW_BYTES,
            label="Apple release raw view-after",
        ),
        expectation=expectation,
        release_id=release_id,
    )
    _require(
        view_after.canonical == view_before.canonical,
        "GitHub Apple release view changed during verification",
    )
    attestation, timestamp_authority = _parse_release_verification(
        _read_private_bytes(
            raw_directory / RAW_VERIFY_NAME,
            maximum=MAX_RELEASE_VERIFY_BYTES,
            label="Apple release raw verification",
        ),
        expectation=expectation,
        release_id=release_id,
        expected_tag_object=tag_object,
        published_at=view_before.published_at,
    )
    observed_at = _observation_timestamp(
        clock,
        not_before=attestation["verified_at"],
    )
    publication = {
        "draft": False,
        "immutable_release": True,
        "observed_at": observed_at,
        "prerelease": True,
        "public_release": True,
        "published_at": view_before.published_at,
        "release_attestation": attestation,
        "release_id": release_id,
        "source": {
            "tag_commit": expectation.tag_commit,
            "tag_object": tag_object,
        },
    }
    projection = {
        "assets": list(view_before.assets),
        "kind": PROJECTION_KIND,
        "publication": publication,
        "release_identity": {
            "repository": REPOSITORY,
            "tag": expectation.tag,
            "url": expectation.release_url,
            "visibility": "PUBLIC",
        },
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "timestamp_authority": timestamp_authority,
    }
    projection_sha256 = _write_projection(projection_output, projection)
    return projection_sha256, expectation, release_id


def _usage() -> str:
    return (
        "usage: apple_release_verification.py collect ASSET_LEDGER "
        "EXPECTED_RELEASE_ID EXPECTED_TAG_OBJECT RAW_DIRECTORY PROJECTION_OUTPUT"
    )


def _main(arguments: Sequence[str]) -> int:
    if len(arguments) != 6 or arguments[0] != "collect":
        print(f"error: {_usage()}", file=sys.stderr)
        return 2
    digest, expectation, release_id = collect_release_verification(
        pathlib.Path(arguments[1]),
        arguments[2],
        arguments[3],
        pathlib.Path(arguments[4]),
        pathlib.Path(arguments[5]),
    )
    print(
        "APPLE_GITHUB_RELEASE_VERIFY_PASS "
        f"assets=4 tag={expectation.tag} release_id={release_id} "
        f"projection_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except AppleReleaseVerificationError as exc:
        raise SystemExit(f"error: {exc}") from None
