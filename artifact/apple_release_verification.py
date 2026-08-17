#!/usr/bin/env python3
"""Collect and sanitize one GitHub Apple release-verification transaction.

This I/O adapter is deliberately independent from the pure Apple publication
receipt contract.  It invokes fixed ``git`` plus one explicit identity-pinned
``gh`` through the repository's bounded subprocess runner, retains private raw
JSON, and publishes only a small PII-safe projection after all samples agree.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, Never

import apple_publication_contract as apple_contract
from bounded_process import BoundedProcessError, BoundedResult, capture_stdout
from evidence_io import (
    EvidenceIOError,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
import github_release_observation as github_release
from git_provenance import (
    GIT,
    GitProvenanceError,
    require_direct_results_only_child,
)
from publication_receipt_io import (
    PublicationReceiptIOError,
    write_private_bytes_noreplace_at,
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
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
APPLE_LEDGER_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-apple-release-worktrees"
)
APPLE_VERIFICATION_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-apple-release-verification"
)
APPLE_RAW_ROOT = APPLE_VERIFICATION_ROOT / "raw"
APPLE_PROJECTION_ROOT = APPLE_VERIFICATION_ROOT / "projections"
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

# Backwards-compatible public fixture constants are aliases to the neutral
# parser's single policy authority.  No Apple-local copy may drift from it.
RELEASE_VIEW_FIELDS = github_release.RELEASE_VIEW_FIELDS
REPOSITORY_VIEW_FIELDS = github_release.REPOSITORY_VIEW_FIELDS
VERIFICATION_RESULT_MEDIA_TYPE = github_release.VERIFICATION_RESULT_MEDIA_TYPE
STATEMENT_TYPE = github_release.STATEMENT_TYPE
RELEASE_PREDICATE_TYPE = github_release.RELEASE_PREDICATE_TYPE
RELEASE_CERTIFICATE_SAN = github_release.RELEASE_CERTIFICATE_SAN
RELEASE_CERTIFICATE_ISSUER = github_release.RELEASE_CERTIFICATE_ISSUER
TIMESTAMP_AUTHORITY_TYPE = github_release.TIMESTAMP_AUTHORITY_TYPE
TIMESTAMP_AUTHORITY_URI = github_release.TIMESTAMP_AUTHORITY_URI

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
SAFE_DIRECTORY_LEAF = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")

class AppleReleaseVerificationError(ValueError):
    """One local or GitHub release observation violates the I/O contract."""


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseExpectation:
    product_version: str
    revision: str
    tag: str
    source_parent_commit: str
    tag_commit: str | None
    asset_sha256: Mapping[str, str]
    expected_prerelease: bool

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


def _normalized_safe_root(
    safe_root: pathlib.Path,
    *,
    label: str,
    required_mode: int | None = None,
) -> pathlib.Path:
    """Return one fixed, owned, canonical directory used as an I/O boundary."""

    root_text = os.path.realpath(os.fspath(safe_root))
    _require(
        safe_root.is_absolute()
        and root_text == os.path.abspath(os.fspath(safe_root)),
        f"{label} safe root must be canonical",
    )
    root = pathlib.Path(root_text)
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise AppleReleaseVerificationError(
            f"cannot inspect {label} safe root"
        ) from exc
    valid = (
        stat.S_ISDIR(metadata.st_mode)
        and not root.is_symlink()
        and metadata.st_uid == os.geteuid()
    )
    if required_mode is not None:
        valid = valid and stat.S_IMODE(metadata.st_mode) == required_mode
    _require(valid, f"{label} safe root is not an owned non-symlink directory")
    return root


def _normalize_path_under_root(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    label: str,
    required_root_mode: int | None = None,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Resolve a CLI path once and prove containment below one fixed root."""

    if not path.is_absolute():
        raise AppleReleaseVerificationError(f"{label} must be absolute")
    root = _normalized_safe_root(
        safe_root,
        label=label,
        required_mode=required_root_mode,
    )
    supplied_text = os.fspath(path)
    normalized_text = os.path.realpath(supplied_text)
    root_text = os.fspath(root)
    if not normalized_text.startswith(root_text + os.sep):
        raise AppleReleaseVerificationError(
            f"{label} is outside its fixed safe root"
        )
    if normalized_text != os.path.abspath(supplied_text):
        raise AppleReleaseVerificationError(
            f"{label} must contain no symlink or traversal aliases"
        )
    return pathlib.Path(normalized_text), root


def _normalize_asset_ledger(path: pathlib.Path) -> pathlib.Path:
    normalized, _root = _normalize_path_under_root(
        path,
        safe_root=APPLE_LEDGER_ROOT,
        label="Apple release asset ledger",
        required_root_mode=0o700,
    )
    try:
        metadata = normalized.lstat()
    except OSError as exc:
        raise AppleReleaseVerificationError(
            "cannot inspect Apple release asset ledger"
        ) from exc
    _require(
        stat.S_ISREG(metadata.st_mode) and not normalized.is_symlink(),
        "Apple release asset ledger must be a non-symlink regular file",
    )
    return normalized


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


@contextlib.contextmanager
def _directory_handle(
    path: pathlib.Path,
    *,
    label: str,
    required_mode: int | None,
) -> Iterator[int]:
    """Close a pinned directory without replacing the primary exception."""

    descriptor = _directory_fd(
        path, label=label, required_mode=required_mode
    )
    primary: BaseException | None = None
    try:
        yield descriptor
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            detail = f"cannot close {label}"
            if primary is not None:
                primary.add_note(detail)
            else:
                raise AppleReleaseVerificationError(detail) from exc


def _require_absent_at(directory_fd: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AppleReleaseVerificationError(f"cannot inspect {label}") from exc
    _fail(f"{label} already exists")


def _normalize_projection_path(path: pathlib.Path) -> pathlib.Path:
    _require(path.is_absolute(), "Apple release projection must be absolute")
    _require(path.name == PROJECTION_NAME, "Apple release projection leaf differs")
    parent, root = _normalize_path_under_root(
        path.parent,
        safe_root=APPLE_PROJECTION_ROOT,
        label="Apple release projection parent",
        required_root_mode=0o700,
    )
    _require(
        parent.parent == root,
        "Apple release projection parent must be a direct safe-root child",
    )
    normalized = parent / PROJECTION_NAME
    if os.path.realpath(os.fspath(normalized)) != os.fspath(normalized):
        raise AppleReleaseVerificationError(
            "Apple release projection must contain no symlink aliases"
        )
    return normalized


def _validate_projection_absent(path: pathlib.Path) -> None:
    with _directory_handle(
        path.parent,
        label="Apple release projection parent",
        required_mode=0o700,
    ) as parent_fd:
        _require_absent_at(parent_fd, PROJECTION_NAME, "Apple release projection")


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


def _normalize_raw_directory_path(path: pathlib.Path) -> pathlib.Path:
    normalized, root = _normalize_path_under_root(
        path,
        safe_root=APPLE_RAW_ROOT,
        label="Apple release raw directory",
        required_root_mode=0o700,
    )
    _require(
        normalized.parent == root,
        "Apple release raw directory must be a direct safe-root child",
    )
    _require(
        SAFE_DIRECTORY_LEAF.fullmatch(normalized.name) is not None,
        "Apple release raw directory leaf is unsafe",
    )
    return normalized


def _create_raw_directory(path: pathlib.Path) -> None:
    with _directory_handle(
        APPLE_RAW_ROOT,
        label="Apple release raw parent",
        required_mode=0o700,
    ) as parent_fd:
        _require_absent_at(parent_fd, path.name, "Apple release raw directory")
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError as exc:
            raise AppleReleaseVerificationError(
                "cannot create Apple release raw directory"
            ) from exc
    with _directory_handle(
        path,
        label="Apple release raw directory",
        required_mode=0o700,
    ):
        pass


def _write_private_bytes_at(
    directory_fd: int,
    name: str,
    data: bytes,
    *,
    label: str,
) -> str:
    try:
        return write_private_bytes_noreplace_at(
            directory_fd,
            name,
            data,
            label=label,
            maximum=max(
                MAX_RELEASE_VERIFY_BYTES,
                MAX_RELEASE_VIEW_BYTES,
                MAX_REPOSITORY_VIEW_BYTES,
            ),
        )
    except PublicationReceiptIOError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def _write_raw_bytes(
    raw_directory: pathlib.Path,
    name: str,
    data: bytes,
    *,
    label: str,
) -> None:
    with _directory_handle(
        raw_directory,
        label="Apple release raw directory",
        required_mode=0o700,
    ) as raw_fd:
        _write_private_bytes_at(raw_fd, name, data, label=label)


def _write_projection(path: pathlib.Path, projection: object) -> str:
    _validate_projection_absent(path)
    payload = (
        json.dumps(projection, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
    ).encode("ascii")
    with _directory_handle(
        path.parent,
        label="Apple release projection parent",
        required_mode=0o700,
    ) as parent_fd:
        return _write_private_bytes_at(
            parent_fd,
            PROJECTION_NAME,
            payload,
            label="Apple release projection",
        )


def load_release_expectation(path: pathlib.Path) -> ReleaseExpectation:
    """Load one private completion or historical expected-assets ledger."""

    path = _normalize_asset_ledger(path)
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
    source_parent_commit = _sha1(
        ledger["source_commit"], "Apple release source commit"
    )
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
    is_historical_prerelease = ledger["kind"] == HISTORICAL_EXPECTATION_KIND
    expected_tag = (
        f"v{product_version}-{revision}"
        if is_historical_prerelease
        else f"v{product_version}"
    )
    _require(
        isinstance(tag, str)
        and SAFE_TAG.fullmatch(tag) is not None
        and tag == expected_tag,
        "Apple release tag differs from its identity",
    )
    hashes = _object(
        ledger["public_assets_sha256"], "Apple release expected asset hashes"
    )
    _exact_keys(
        hashes,
        frozenset(apple_contract.APPLE_PUBLIC_ASSET_NAMES),
        "Apple release expected asset hashes",
    )
    asset_hashes = {
        name: _sha256(hashes[name], f"Apple release expected digest for {name}")
        for name in apple_contract.APPLE_PUBLIC_ASSET_NAMES
    }
    return ReleaseExpectation(
        product_version=product_version,
        revision=revision,
        tag=tag,
        source_parent_commit=source_parent_commit,
        tag_commit=(
            source_parent_commit if is_historical_prerelease else None
        ),
        asset_sha256=asset_hashes,
        expected_prerelease=is_historical_prerelease,
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


def _gh_tool_identity() -> github_release.GitHubCliIdentity:
    try:
        return github_release.select_github_cli()
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def _resample_gh_tool(expected: github_release.GitHubCliIdentity) -> None:
    try:
        github_release.resample_github_cli(expected)
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def _process_environment(source: Mapping[str, str]) -> dict[str, str]:
    try:
        return github_release.github_cli_environment(source)
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def _git_environment() -> dict[str, str]:
    return github_release.git_observation_environment()


def _capture_gh_command(
    arguments: Sequence[str],
    *,
    tool: github_release.GitHubCliIdentity,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: CommandRunner,
) -> bytes:
    try:
        return github_release.capture_github_cli(
            tool,
            arguments,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            environment=environment,
            label=label,
            runner=runner,
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def observe_release_id(
    asset_ledger: pathlib.Path,
    *,
    runner: CommandRunner = capture_stdout,
    source_environment: Mapping[str, str] | None = None,
) -> int:
    """Return the bounded stable release ID through the pinned GitHub CLI."""

    ledger = _normalize_asset_ledger(asset_ledger)
    expectation = load_release_expectation(ledger)
    environment = _process_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = _gh_tool_identity()
    raw = _capture_gh_command(
        [
            "release",
            "view",
            expectation.tag,
            "--repo",
            GH_REPOSITORY_ARGUMENT,
            "--json",
            "databaseId",
        ],
        tool=tool,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=1024,
        environment=environment,
        label="GitHub Apple release ID observation",
        runner=runner,
    )
    try:
        value = parse_strict_json_bytes(raw, label="GitHub Apple release ID")
    except EvidenceIOError as exc:
        raise AppleReleaseVerificationError(
            "GitHub Apple release ID is not strict JSON"
        ) from exc
    document = _object(value, "GitHub Apple release ID")
    _exact_keys(document, frozenset({"databaseId"}), "GitHub Apple release ID")
    database_id = document["databaseId"]
    _require(
        type(database_id) is int and 1 <= database_id <= MAX_RELEASE_ID,
        "GitHub Apple release ID is not a bounded positive integer",
    )
    return database_id


def observe_tag_object(
    asset_ledger: pathlib.Path,
    *,
    runner: CommandRunner = capture_stdout,
    source_environment: Mapping[str, str] | None = None,
) -> str:
    """Return the annotated tag object through fixed local Git policy."""

    source = os.environ if source_environment is None else source_environment
    _require(
        not any(name.startswith("GIT_") for name in source),
        "Apple tag observation rejects caller Git environment overrides",
    )
    ledger = _normalize_asset_ledger(asset_ledger)
    expectation = load_release_expectation(ledger)
    reference = f"refs/tags/{expectation.tag}"
    tag_type = _git_line(
        GIT,
        ["cat-file", "-t", reference],
        environment=_git_environment(),
        label="Apple release tag type observation",
        runner=runner,
    )
    _require(tag_type == "tag", "Apple release tag is not annotated")
    return _sha1(
        _git_line(
            GIT,
            ["rev-parse", "--verify", reference],
            environment=_git_environment(),
            label="Apple release tag object observation",
            runner=runner,
        ),
        "Apple release tag object",
    )


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
        HEX_40.fullmatch(tag_commit) is not None,
        "Apple release peeled commit is malformed",
    )
    if expectation.expected_prerelease:
        _require(
            tag_commit == expectation.tag_commit,
            "Apple release peeled commit differs",
        )
    else:
        if expectation.tag_commit is not None:
            _require(
                tag_commit == expectation.tag_commit,
                "Apple release peeled commit differs",
            )
        _require(
            tag_commit != expectation.source_parent_commit,
            "Apple stable tag commit must differ from its source parent",
        )
        try:
            require_direct_results_only_child(
                REPOSITORY_ROOT,
                expectation.source_parent_commit,
                tag_commit,
            )
        except GitProvenanceError as exc:
            raise AppleReleaseVerificationError(
                "cannot establish the Apple stable source/tag boundary"
            ) from exc
    return tag_object, tag_commit


def _github_release_policy(
    expectation: ReleaseExpectation,
    *,
    release_id: int,
    tag_object: str | None,
) -> github_release.ReleasePolicy:
    _require(
        expectation.tag_commit is not None,
        "Apple release tag commit has not been observed",
    )
    return github_release.ReleasePolicy(
        repository=REPOSITORY,
        repository_url=REPOSITORY_URL,
        release_url=expectation.release_url,
        download_prefix=RELEASE_DOWNLOAD_PREFIX,
        api_asset_prefix=API_ASSET_PREFIX,
        tag_subject_uri=f"{TAG_SUBJECT_PREFIX}{expectation.tag}",
        tag=expectation.tag,
        tag_commit=expectation.tag_commit,
        tag_object=tag_object,
        asset_names=apple_contract.APPLE_PUBLIC_ASSET_NAMES,
        expected_prerelease=expectation.expected_prerelease,
        expected_release_id=release_id,
        expected_sha256=expectation.asset_sha256,
        expected_content_types=apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES,
        require_asset_order=True,
    )


def _parse_release_view(
    data: bytes,
    *,
    expectation: ReleaseExpectation,
    release_id: int,
) -> ReleaseView:
    try:
        parsed = github_release.parse_release_view(
            data,
            policy=_github_release_policy(
                expectation,
                release_id=release_id,
                tag_object=None,
            ),
            label="GitHub Apple release view",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc
    return ReleaseView(
        published_at=parsed.published_at,
        assets=parsed.assets,
        canonical=parsed.canonical,
    )


def _parse_repository_view(data: bytes) -> RepositoryView:
    try:
        parsed = github_release.parse_repository_view(
            data,
            policy=github_release.RepositoryPolicy(
                repository=REPOSITORY,
                repository_url=REPOSITORY_URL,
            ),
            label="GitHub repository visibility view",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc
    return RepositoryView(canonical=parsed.canonical)


def _expected_subjects(
    expectation: ReleaseExpectation, expected_tag_object: str
) -> list[dict[str, object]]:
    try:
        return github_release.expected_subjects(
            _github_release_policy(
                expectation,
                release_id=1,
                tag_object=expected_tag_object,
            )
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc


def _parse_release_verification(
    data: bytes,
    *,
    expectation: ReleaseExpectation,
    release_id: int,
    expected_tag_object: str,
    published_at: str,
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        parsed = github_release.parse_release_verification(
            data,
            policy=_github_release_policy(
                expectation,
                release_id=release_id,
                tag_object=expected_tag_object,
            ),
            release_id=release_id,
            published_at=published_at,
            label="GitHub Apple release verification",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise AppleReleaseVerificationError(str(exc)) from exc
    return parsed.projection(include_verified_at=True), parsed.timestamp_authority()


def _validate_raw_directory(path: pathlib.Path) -> None:
    with _directory_handle(
        path,
        label="Apple release raw directory",
        required_mode=0o700,
    ) as descriptor:
        try:
            actual = set(os.listdir(descriptor))
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
) -> tuple[str, ReleaseExpectation, int]:
    """Collect one local/remote transaction and publish its safe projection."""

    _normalized_safe_root(
        APPLE_VERIFICATION_ROOT,
        label="Apple release verification",
        required_mode=0o700,
    )
    asset_ledger = _normalize_asset_ledger(asset_ledger)
    raw_directory = _normalize_raw_directory_path(raw_directory)
    projection_output = _normalize_projection_path(projection_output)
    _validate_io_path_disjointness(
        asset_ledger,
        raw_directory,
        projection_output,
    )
    _validate_projection_absent(projection_output)
    expectation = load_release_expectation(asset_ledger)
    release_id = _release_id(expected_release_id)
    tag_object = _sha1(expected_tag_object, "expected Apple release tag object")
    gh_environment = _process_environment(
        os.environ if source_environment is None else source_environment
    )
    git_environment = _git_environment()
    gh = _gh_tool_identity()
    _create_raw_directory(raw_directory)

    local_before = _verify_local_tag(
        GIT,
        expectation,
        tag_object,
        environment=git_environment,
        runner=runner,
    )
    expectation = dataclasses.replace(
        expectation,
        tag_commit=local_before[1],
    )
    repository_arguments = [
        "repo",
        "view",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(REPOSITORY_VIEW_FIELDS),
    ]
    view_arguments = [
        "release",
        "view",
        expectation.tag,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(RELEASE_VIEW_FIELDS),
    ]
    verify_arguments = [
        "release",
        "verify",
        expectation.tag,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--format",
        "json",
    ]
    repository_before_raw = _capture_gh_command(
        repository_arguments,
        tool=gh,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=gh_environment,
        label="GitHub repository visibility before observation",
        runner=runner,
    )
    _write_raw_bytes(
        raw_directory,
        RAW_REPOSITORY_BEFORE_NAME,
        repository_before_raw,
        label="Apple release raw repository-before",
    )
    repository_before = _parse_repository_view(
        _read_private_bytes(
            raw_directory / RAW_REPOSITORY_BEFORE_NAME,
            maximum=MAX_REPOSITORY_VIEW_BYTES,
            label="Apple release raw repository-before",
        )
    )
    view_before_raw = _capture_gh_command(
        view_arguments,
        tool=gh,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=gh_environment,
        label="GitHub Apple release view-before observation",
        runner=runner,
    )
    _write_raw_bytes(
        raw_directory,
        RAW_VIEW_BEFORE_NAME,
        view_before_raw,
        label="Apple release raw view-before",
    )

    verify_raw = _capture_gh_command(
        verify_arguments,
        tool=gh,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VERIFY_BYTES,
        environment=gh_environment,
        label="GitHub Apple release attestation verification",
        runner=runner,
    )
    _write_raw_bytes(
        raw_directory,
        RAW_VERIFY_NAME,
        verify_raw,
        label="Apple release raw verification",
    )

    view_after_raw = _capture_gh_command(
        view_arguments,
        tool=gh,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=gh_environment,
        label="GitHub Apple release view-after observation",
        runner=runner,
    )
    _write_raw_bytes(
        raw_directory,
        RAW_VIEW_AFTER_NAME,
        view_after_raw,
        label="Apple release raw view-after",
    )

    repository_after_raw = _capture_gh_command(
        repository_arguments,
        tool=gh,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=gh_environment,
        label="GitHub repository visibility after observation",
        runner=runner,
    )
    _write_raw_bytes(
        raw_directory,
        RAW_REPOSITORY_AFTER_NAME,
        repository_after_raw,
        label="Apple release raw repository-after",
    )

    local_after = _verify_local_tag(
        GIT,
        expectation,
        tag_object,
        environment=git_environment,
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
        "prerelease": expectation.expected_prerelease,
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
        "usage: apple_release_verification.py release-id ASSET_LEDGER | "
        "tag-object ASSET_LEDGER | collect ASSET_LEDGER EXPECTED_RELEASE_ID "
        "EXPECTED_TAG_OBJECT RAW_DIRECTORY PROJECTION_OUTPUT"
    )


def _main(arguments: Sequence[str]) -> int:
    if len(arguments) == 2 and arguments[0] == "release-id":
        print(observe_release_id(pathlib.Path(arguments[1])))
        return 0
    if len(arguments) == 2 and arguments[0] == "tag-object":
        print(observe_tag_object(pathlib.Path(arguments[1])))
        return 0
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
