#!/usr/bin/env python3
"""Domain-neutral GitHub release observation and restricted mutation transport.

The module owns the single pinned GitHub CLI execution boundary, pure parsers
for its already-bounded output, and the two narrowly shaped JSON/asset mutation
transports used by the stable publication coordinator.  Callers retain policy,
transaction ordering, private raw bytes, and domain receipt construction.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Never

from bounded_process import (
    BoundedProcessError,
    BoundedResult,
    capture_stdout,
    write_stdout_at,
)
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    consume_regular_snapshot,
    parse_strict_json_bytes,
)

try:
    import pwd
except ImportError:
    pwd = None


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
MUTABLE_RELEASE_VIEW_FIELDS = (
    "apiUrl",
    "assets",
    "body",
    "databaseId",
    "isDraft",
    "isImmutable",
    "isPrerelease",
    "name",
    "publishedAt",
    "tagName",
    "targetCommitish",
    "uploadUrl",
    "url",
)
MUTABLE_RELEASE_VIEW_KEYS = frozenset(MUTABLE_RELEASE_VIEW_FIELDS)
RELEASE_LIST_FIELDS = (
    "createdAt",
    "isDraft",
    "isImmutable",
    "isLatest",
    "isPrerelease",
    "name",
    "publishedAt",
    "tagName",
)
RELEASE_LIST_KEYS = frozenset(RELEASE_LIST_FIELDS)
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
GITHUB_CLI_PATH = pathlib.Path(
    "/opt/homebrew/Cellar/gh/2.94.0/bin/gh"
)
GITHUB_CLI_SHA256 = (
    "2ef6c63bc52dc32bc42366215f91a51b009950791806209fd7f6fc7f5b668ba2"
)
MAX_GITHUB_CLI_BYTES = 512 * 1024 * 1024
GITHUB_CLI_TEMP_ROOT = pathlib.Path("/tmp")
GITHUB_CREDENTIAL_ENVIRONMENT = ("GH_TOKEN", "GITHUB_TOKEN")
GITHUB_REPOSITORY = "billlza/q-periapt"
STABLE_TAG_REFS = (
    "refs/tags/v0.1.3",
    "refs/tags/abi2-platforms-v0.1.3",
)
# Ruleset protection must keep every stable release tag immutable, not only the
# current one: the earlier stable tags remain permanent, tagged-unpublished
# history, so their update/deletion protection must never silently lapse. State
# observation (absent/apple_only/exact transitions) uses only the current
# STABLE_TAG_REFS above, but the protection observer checks this full set.
PROTECTED_STABLE_TAG_REFS = (
    "refs/tags/v0.1.0",
    "refs/tags/abi2-platforms-v0.1.0",
    "refs/tags/v0.1.1",
    "refs/tags/abi2-platforms-v0.1.1",
    "refs/tags/v0.1.2",
    "refs/tags/abi2-platforms-v0.1.2",
    "refs/tags/v0.1.3",
    "refs/tags/abi2-platforms-v0.1.3",
)
MAX_TAG_RULESETS = 32
MAX_STABLE_TAG_MATCHES = 64
MAX_TAG_RULESET_LIST_BYTES = 4 * 1024 * 1024
MAX_TAG_RULESET_BYTES = 4 * 1024 * 1024
MAX_STABLE_TAG_REFERENCE_BYTES = 4 * 1024 * 1024
MAX_STABLE_TAG_OBJECT_BYTES = 4 * 1024 * 1024
MAX_STABLE_COMMIT_OBJECT_BYTES = 4 * 1024 * 1024
GITHUB_API_VERSION = "2026-03-10"
DANGEROUS_GITHUB_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "GH_CONFIG_DIR",
        "GH_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_REPO",
        "GITHUB_ENTERPRISE_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "PIP_CERT",
        "PYTHONHTTPSVERIFY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SSLKEYLOGFILE",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
SAFE_NODE_ID = re.compile(r"^[0-9A-Za-z_-]+$")
SAFE_ASSET_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
SIMPLE_MEDIA_TYPE = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
)


class GitHubReleaseObservationError(ValueError):
    """GitHub release JSON violates an exact immutable-release policy."""


class GitHubCliExecutionError(GitHubReleaseObservationError):
    """A typed subprocess failure that callers may classify without text parsing."""

    def __init__(
        self,
        label: str,
        *,
        error_kind: str | None,
        returncode: int | None,
    ) -> None:
        self.error_kind = error_kind
        self.returncode = returncode
        super().__init__(f"{label} failed safely")


class GitHubLocalIntegrityError(GitHubReleaseObservationError):
    """A local gh executable, process, input, or state boundary became unsafe."""

    def __init__(
        self,
        message: str,
        *,
        preceding_type: str | None = None,
        error_kind: str | None = None,
        returncode: int | None = None,
        signal_number: int | None = None,
        cleanup_ambiguous: bool = False,
    ) -> None:
        super().__init__(message)
        self.preceding_type = preceding_type
        self.error_kind = error_kind
        self.returncode = returncode
        self.signal_number = signal_number
        self.cleanup_ambiguous = cleanup_ambiguous


class GitHubMutationInputIntegrityError(GitHubLocalIntegrityError):
    """A pinned mutation body changed across the subprocess boundary."""


class GitHubProcessOwnershipIntegrityError(GitHubLocalIntegrityError):
    """A failed GitHub subprocess may still own an unconfirmed live process."""

    def __init__(
        self,
        message: str,
        *,
        error_kind: str,
        signal_number: int | None = None,
    ) -> None:
        super().__init__(
            message,
            preceding_type="BoundedProcessError",
            error_kind=error_kind,
            signal_number=signal_number,
            cleanup_ambiguous=True,
        )


class GitHubCliEnvironmentIntegrityError(GitHubLocalIntegrityError):
    """The one-command gh home/config/state/cache boundary became unsafe."""


class GitHubCliIdentityIntegrityError(GitHubLocalIntegrityError):
    """The source-pinned gh executable identity changed around a command."""


def _sanitized_failure_fields(error: BaseException | None) -> dict[str, object]:
    fields: dict[str, object] = {
        "preceding_type": None if error is None else type(error).__name__,
        "error_kind": None,
        "returncode": None,
        "signal_number": None,
        "cleanup_ambiguous": False,
    }
    if isinstance(error, GitHubCliExecutionError):
        fields["error_kind"] = error.error_kind
        fields["returncode"] = error.returncode
    elif isinstance(error, GitHubLocalIntegrityError):
        fields["error_kind"] = error.error_kind
        fields["returncode"] = error.returncode
        fields["signal_number"] = error.signal_number
        fields["cleanup_ambiguous"] = error.cleanup_ambiguous
    elif isinstance(error, BoundedProcessError):
        fields["error_kind"] = error.kind
        fields["signal_number"] = error.signal_number
        fields["cleanup_ambiguous"] = error.cleanup_ambiguous
    elif isinstance(error, SystemExit) and type(error.code) is int:
        if 129 <= error.code <= 255:
            fields["signal_number"] = error.code - 128
    return fields


def _local_integrity_error(
    error_type: type[GitHubLocalIntegrityError],
    message: str,
    preceding: BaseException | None,
) -> GitHubLocalIntegrityError:
    fields = _sanitized_failure_fields(preceding)
    preceding_type = fields["preceding_type"]
    error_kind = fields["error_kind"]
    returncode = fields["returncode"]
    signal_number = fields["signal_number"]
    cleanup_ambiguous = fields["cleanup_ambiguous"]
    return error_type(
        message,
        preceding_type=(
            preceding_type if isinstance(preceding_type, str) else None
        ),
        error_kind=error_kind if isinstance(error_kind, str) else None,
        returncode=returncode if type(returncode) is int else None,
        signal_number=(
            signal_number if type(signal_number) is int else None
        ),
        cleanup_ambiguous=(
            cleanup_ambiguous if type(cleanup_ambiguous) is bool else False
        ),
    )


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
    expected_prerelease: bool
    expected_release_id: int | None = None
    expected_sha256: Mapping[str, str] | None = None
    expected_content_types: Mapping[str, str] | None = None
    require_asset_order: bool = True


@dataclasses.dataclass(frozen=True, slots=True)
class MutableReleasePolicy:
    repository: str
    tag: str
    tag_commit: str
    title: str
    body: str
    asset_names: tuple[str, ...]
    expected_sha256: Mapping[str, str]
    expected_sizes: Mapping[str, int]
    expected_content_types: Mapping[str, str]


@dataclasses.dataclass(frozen=True, slots=True)
class MutableReleaseAsset:
    asset_id: int
    node_id: str
    name: str
    size: int
    sha256: str
    content_type: str
    state: str
    created_at: str
    updated_at: str


@dataclasses.dataclass(frozen=True, slots=True)
class MutableReleaseView:
    release_id: int
    tag: str
    draft: bool
    immutable: bool
    prerelease: bool
    is_latest: bool
    published_at: str | None
    assets: tuple[MutableReleaseAsset, ...]
    canonical: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseListTarget:
    tag: str
    title: str
    draft: bool
    immutable: bool
    latest: bool
    prerelease: bool
    published_at: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseListObservation:
    targets: tuple[ReleaseListTarget, ...]
    latest_tag: str | None
    canonical: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class MutableReleaseTransactionObservation:
    repository_canonical: bytes
    immutable_enabled: bool
    immutable_enforced_by_owner: bool
    latest_tag: str | None
    releases: tuple[MutableReleaseView | None, MutableReleaseView | None]
    canonical: bytes


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


@dataclasses.dataclass(frozen=True, slots=True)
class GitHubCliIdentity:
    path: str
    device: int
    inode: int
    mode: int
    uid: int
    link_count: int
    size: int
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class StableTagProtectionObservation:
    repository: str
    ruleset_ids: tuple[int, ...]
    tag_refs: tuple[str, ...]
    observation_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class StableTagStateObservation:
    repository: str
    state: str
    tag_refs: tuple[str, ...]
    tag_objects: tuple[str, ...]
    commit: str | None
    tree: str | None
    observation_sha256: str


GitHubCommandRunner = Callable[..., BoundedResult]
GitHubSinkRunner = Callable[..., BoundedResult]
GitHubInputRunner = Callable[..., BoundedResult]


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


def _select_github_cli_untyped() -> GitHubCliIdentity:
    """Snapshot the sole source-pinned GitHub CLI authority."""

    supplied = GITHUB_CLI_PATH
    _require(
        isinstance(supplied, pathlib.Path) and supplied.is_absolute(),
        "pinned GitHub CLI path must be explicit and absolute",
    )
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise GitHubReleaseObservationError(
            "cannot resolve the pinned GitHub CLI path"
        ) from exc
    _require(
        resolved == supplied,
        "pinned GitHub CLI path must be canonical and must not be a symlink",
    )

    observed: os.stat_result | None = None
    uid_getter = getattr(os, "geteuid", None)
    _require(
        os.name == "posix" and pwd is not None and callable(uid_getter),
        "pinned GitHub CLI selection requires a POSIX account",
    )

    def validate_metadata(metadata: os.stat_result) -> None:
        nonlocal observed
        mode = stat.S_IMODE(metadata.st_mode)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid in {0, uid_getter()}
            and metadata.st_nlink == 1
            and mode & 0o111 != 0
            and mode & 0o022 == 0,
            "pinned GitHub CLI metadata is unsafe",
        )
        observed = metadata

    try:
        snapshot: FileDigestSnapshot = consume_regular_snapshot(
            resolved,
            maximum=MAX_GITHUB_CLI_BYTES,
            label="pinned GitHub CLI",
            validate_metadata=validate_metadata,
        )
    except EvidenceIOError as exc:
        raise GitHubReleaseObservationError(
            "cannot safely snapshot the pinned GitHub CLI"
        ) from exc
    _require(
        snapshot.size > 0 and observed is not None,
        "pinned GitHub CLI is empty",
    )
    _require(
        snapshot.sha256 == GITHUB_CLI_SHA256,
        "pinned GitHub CLI digest differs from the source policy",
    )
    if observed is None:
        _fail("pinned GitHub CLI metadata was not observed")
    return GitHubCliIdentity(
        path=str(resolved),
        device=observed.st_dev,
        inode=observed.st_ino,
        mode=observed.st_mode,
        uid=observed.st_uid,
        link_count=observed.st_nlink,
        size=snapshot.size,
        sha256=snapshot.sha256,
    )


def select_github_cli() -> GitHubCliIdentity:
    """Select the source-pinned gh binary with a typed local boundary error."""

    try:
        return _select_github_cli_untyped()
    except GitHubLocalIntegrityError:
        raise
    except GitHubReleaseObservationError as exc:
        raise _local_integrity_error(
            GitHubCliIdentityIntegrityError,
            str(exc),
            exc,
        ) from exc


def resample_github_cli(expected: GitHubCliIdentity) -> None:
    """Reject path, metadata, inode, size, or byte drift from startup."""

    if not isinstance(expected, GitHubCliIdentity):
        raise GitHubCliIdentityIntegrityError(
            "pinned GitHub CLI identity is malformed"
        )
    try:
        observed = select_github_cli()
    except GitHubReleaseObservationError as exc:
        raise GitHubCliIdentityIntegrityError(
            "pinned GitHub CLI identity or bytes changed during observation"
        ) from exc
    if observed != expected:
        raise GitHubCliIdentityIntegrityError(
            "pinned GitHub CLI identity or bytes changed during observation"
        )


def github_cli_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Build the only credential-bearing environment admitted for ``gh``."""

    overridden = sorted(
        name
        for name in source
        if name.startswith("GIT_")
        or (
            name.startswith("GH_")
            and name not in GITHUB_CREDENTIAL_ENVIRONMENT
        )
        or name in DANGEROUS_GITHUB_ENVIRONMENT
    )
    _require(
        not overridden,
        "GitHub observation rejects Git/GitHub/network trust overrides",
    )
    credentials = [
        name for name in GITHUB_CREDENTIAL_ENVIRONMENT if source.get(name)
    ]
    _require(
        len(credentials) == 1,
        "GitHub observation requires exactly one GitHub credential variable",
    )
    credential = credentials[0]
    credential_value = source[credential]
    _require(
        isinstance(credential_value, str)
        and 0 < len(credential_value) <= 4_096
        and "\x00" not in credential_value,
        "GitHub credential value is malformed",
    )
    environment = {
        credential: credential_value,
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PAGER": "cat",
        "GH_PROMPT_DISABLED": "1",
        "GH_TELEMETRY": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": _github_account_home(),
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
    }
    return _validated_github_cli_environment(environment)


def _github_account_home() -> str:
    try:
        _require(
            os.name == "posix" and pwd is not None,
            "GitHub observation account requires POSIX passwd data",
        )
        uid_getter = getattr(os, "geteuid", None)
        _require(
            callable(uid_getter),
            "GitHub observation account requires a POSIX user identity",
        )
        account_home = pwd.getpwuid(uid_getter()).pw_dir
    except (KeyError, OSError) as exc:
        raise GitHubReleaseObservationError(
            "cannot determine the fixed GitHub observation account home"
        ) from exc
    _require(
        isinstance(account_home, str) and pathlib.Path(account_home).is_absolute(),
        "GitHub observation account home is not absolute",
    )
    return account_home


def _validated_github_cli_environment(
    environment: Mapping[str, str],
) -> dict[str, str]:
    credentials = [
        name for name in GITHUB_CREDENTIAL_ENVIRONMENT if environment.get(name)
    ]
    _require(
        len(credentials) == 1,
        "GitHub command requires exactly one credential variable",
    )
    credential = credentials[0]
    credential_value = environment[credential]
    static = {
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_PAGER": "cat",
        "GH_PROMPT_DISABLED": "1",
        "GH_TELEMETRY": "0",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": _github_account_home(),
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
        "TERM": "dumb",
    }
    _require(
        isinstance(credential_value, str)
        and 0 < len(credential_value) <= 4_096
        and "\x00" not in credential_value
        and set(environment) == set(static) | {credential}
        and all(environment.get(name) == value for name, value in static.items()),
        "GitHub command environment differs from the fixed minimal policy",
    )
    return {credential: credential_value, **static}


def git_observation_environment() -> dict[str, str]:
    """Return a credential-free environment for fixed local Git sampling."""

    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def capture_github_cli(
    tool: GitHubCliIdentity,
    arguments: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubCommandRunner = capture_stdout,
) -> bytes:
    """Run one bounded ``gh`` command between exact tool resamples."""

    argv = _github_cli_argv(tool, arguments)
    with _isolated_github_cli_environment(environment) as selected_environment:
        result = _execute_github_cli(
            tool,
            lambda: runner(
                argv,
                timeout_seconds=timeout_seconds,
                maximum_bytes=maximum_bytes,
                stderr=subprocess.DEVNULL,
                environment=selected_environment,
            ),
            label=label,
        )
    _require(
        isinstance(result.stdout, bytes) and bool(result.stdout),
        f"{label} returned empty output",
    )
    return result.stdout


def write_github_cli_stdout_at(
    tool: GitHubCliIdentity,
    arguments: Sequence[str],
    *,
    output_directory_fd: int,
    output_name: str,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubSinkRunner = write_stdout_at,
) -> BoundedResult:
    """Stream bounded ``gh`` stdout atomically between tool resamples."""

    argv = _github_cli_argv(tool, arguments)
    with _isolated_github_cli_environment(environment) as selected_environment:
        return _execute_github_cli(
            tool,
            lambda: runner(
                argv,
                output_directory_fd=output_directory_fd,
                output_name=output_name,
                timeout_seconds=timeout_seconds,
                maximum_bytes=maximum_bytes,
                stderr=subprocess.DEVNULL,
                environment=selected_environment,
            ),
            label=label,
        )


def _pinned_input_snapshot(
    descriptor: int,
    *,
    expected_size: int,
    expected_sha256: str,
    label: str,
    require_zero_offset: bool,
) -> tuple[int, int, int, int, int, int, int, int]:
    _require(
        type(descriptor) is int
        and descriptor >= 0
        and type(expected_size) is int
        and expected_size > 0,
        f"{label} descriptor or size is invalid",
    )
    _sha256(expected_sha256, f"{label} SHA-256")
    try:
        metadata = os.fstat(descriptor)
        offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    except OSError as exc:
        raise GitHubReleaseObservationError(
            f"cannot inspect {label} descriptor"
        ) from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o600
        and metadata.st_nlink == 1
        and metadata.st_size == expected_size,
        f"{label} must pin one owned mode-0600 single-link file",
    )
    if require_zero_offset:
        _require(offset == 0, f"{label} descriptor offset is not zero")
    digest = hashlib.sha256()
    consumed = 0
    try:
        while consumed < expected_size:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, expected_size - consumed),
                consumed,
            )
            _require(chunk, f"{label} ended before its declared size")
            digest.update(chunk)
            consumed += len(chunk)
        trailing = os.pread(descriptor, 1, expected_size)
    except OSError as exc:
        raise GitHubReleaseObservationError(f"cannot read {label}") from exc
    _require(
        consumed == expected_size
        and trailing == b""
        and digest.hexdigest() == expected_sha256,
        f"{label} bytes differ",
    )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _execute_github_api_input(
    tool: GitHubCliIdentity,
    arguments: Sequence[str],
    *,
    input_fd: int,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubInputRunner,
) -> bytes:
    identity = _pinned_input_snapshot(
        input_fd,
        expected_size=expected_size,
        expected_sha256=expected_sha256,
        label=label,
        require_zero_offset=True,
    )
    argv = _github_cli_argv(tool, arguments)
    result: BoundedResult | None = None
    primary_error: BaseException | None = None
    try:
        with _isolated_github_cli_environment(environment) as selected_environment:
            result = _execute_github_cli(
                tool,
                lambda: runner(
                    argv,
                    timeout_seconds=timeout_seconds,
                    maximum_bytes=maximum_bytes,
                    stdin_fd=input_fd,
                    stderr=subprocess.DEVNULL,
                    environment=selected_environment,
                ),
                label=label,
            )
    except BaseException as exc:
        primary_error = exc
    post_error: BaseException | None = None
    try:
        after = _pinned_input_snapshot(
            input_fd,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            label=label,
            require_zero_offset=False,
        )
        _require(
            after == identity,
            f"{label} identity changed during GitHub API execution",
        )
    except BaseException as exc:
        post_error = exc
    if post_error is not None:
        integrity = _local_integrity_error(
            GitHubMutationInputIntegrityError,
            f"{label} input integrity changed during the mutation boundary",
            primary_error,
        )
        raise integrity from post_error
    if primary_error is not None:
        raise primary_error
    try:
        final_offset = os.lseek(input_fd, 0, os.SEEK_CUR)
    except OSError as exc:
        raise GitHubMutationInputIntegrityError(
            f"cannot inspect {label} final input offset",
            preceding_type=type(exc).__name__,
        ) from exc
    if final_offset != expected_size:
        raise GitHubMutationInputIntegrityError(
            f"{label} did not consume the exact declared input length"
        )
    if not isinstance(result, BoundedResult) or result.stdout != b"":
        raise GitHubMutationInputIntegrityError(
            f"{label} unexpectedly returned output"
        )
    return result.stdout


def execute_github_api_json_mutation(
    tool: GitHubCliIdentity,
    *,
    method: str,
    endpoint: str,
    input_fd: int,
    input_size: int,
    input_sha256: str,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubInputRunner = capture_stdout,
) -> bytes:
    """Execute one fixed REST JSON mutation from one pinned stdin file."""

    collection = f"/repos/{GITHUB_REPOSITORY}/releases"
    item = re.fullmatch(
        rf"/repos/{re.escape(GITHUB_REPOSITORY)}/releases/[1-9][0-9]*",
        endpoint,
    )
    _require(
        (method == "POST" and endpoint == collection)
        or (method == "PATCH" and item is not None),
        "GitHub JSON mutation endpoint differs",
    )
    arguments = (
        "api",
        "--hostname",
        "github.com",
        "--method",
        method,
        "--silent",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
        "-H",
        "Content-Type: application/json",
        "-H",
        f"Content-Length: {input_size}",
        "--input",
        "-",
        endpoint,
    )
    return _execute_github_api_input(
        tool,
        arguments,
        input_fd=input_fd,
        expected_size=input_size,
        expected_sha256=input_sha256,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        environment=environment,
        label=label,
        runner=runner,
    )


def execute_github_api_asset_upload(
    tool: GitHubCliIdentity,
    *,
    release_id: int,
    asset_name: str,
    content_type: str,
    input_fd: int,
    input_size: int,
    input_sha256: str,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubInputRunner = capture_stdout,
) -> bytes:
    """Upload one release asset with the sole admitted one-call API shape."""

    _positive_integer(release_id, "GitHub upload release ID")
    _require(
        isinstance(asset_name, str)
        and SAFE_ASSET_NAME.fullmatch(asset_name) is not None,
        "GitHub upload asset name differs",
    )
    _require(
        isinstance(content_type, str)
        and SIMPLE_MEDIA_TYPE.fullmatch(content_type) is not None,
        "GitHub upload content type is malformed",
    )
    encoded_name = urllib.parse.quote(asset_name, safe="")
    endpoint = (
        f"https://uploads.github.com/repos/{GITHUB_REPOSITORY}/releases/"
        f"{release_id}/assets"
        f"?name={encoded_name}"
    )
    arguments = (
        "api",
        "--hostname",
        "github.com",
        "--method",
        "POST",
        "--silent",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
        "-H",
        f"Content-Type: {content_type}",
        "-H",
        f"Content-Length: {input_size}",
        "--input",
        "-",
        endpoint,
    )
    return _execute_github_api_input(
        tool,
        arguments,
        input_fd=input_fd,
        expected_size=input_size,
        expected_sha256=input_sha256,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        environment=environment,
        label=label,
        runner=runner,
    )


class _IsolatedGitHubCliEnvironment:
    """Own one complete disposable gh home/config/state/cache authority."""

    def __init__(self, environment: Mapping[str, str]) -> None:
        self._environment = _validated_github_cli_environment(environment)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._identities: dict[str, tuple[int, int, int, int]] = {}
        self._descriptors: dict[str, int] = {}

    def __enter__(self) -> dict[str, str]:
        try:
            root = _validated_github_cli_temp_root()
            self._temporary = tempfile.TemporaryDirectory(
                prefix="qperiapt-gh-config-",
                dir=root,
            )
            directory = pathlib.Path(self._temporary.name)
            os.chmod(directory, 0o700)
            for name in ("home", "config", "state", "cache"):
                child = directory / name
                child.mkdir(mode=0o700)
                os.chmod(child, 0o700)
            for name, path in {
                "root": directory,
                "home": directory / "home",
                "config": directory / "config",
                "state": directory / "state",
                "cache": directory / "cache",
            }.items():
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                )
                self._descriptors[name] = descriptor
                self._identities[name] = _github_cli_private_directory_identity(
                    os.fstat(descriptor)
                )
            _require(
                sorted(os.listdir(directory)) == ["cache", "config", "home", "state"],
                "isolated GitHub CLI root inventory differs",
            )
        except (GitHubReleaseObservationError, OSError) as exc:
            close_error: OSError | None = None
            for descriptor in self._descriptors.values():
                try:
                    os.close(descriptor)
                except OSError as close_exc:
                    close_error = close_error or close_exc
            self._descriptors = {}
            self._identities = {}
            cleanup_error = self._cleanup()
            if close_error is not None or cleanup_error is not None:
                raise _local_integrity_error(
                    GitHubCliEnvironmentIntegrityError,
                    "cannot clean a failed isolated GitHub CLI environment",
                    exc,
                ) from (close_error or cleanup_error)
            raise _local_integrity_error(
                GitHubCliEnvironmentIntegrityError,
                "cannot create the isolated GitHub CLI configuration",
                exc,
            ) from exc
        return {
            **self._environment,
            "HOME": str(directory / "home"),
            "GH_CONFIG_DIR": str(directory / "config"),
            "XDG_STATE_HOME": str(directory / "state"),
            "XDG_CACHE_HOME": str(directory / "cache"),
        }

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> bool:
        del exception_type, traceback
        preceding = exception if isinstance(exception, BaseException) else None
        integrity_error: GitHubCliEnvironmentIntegrityError | None = None
        try:
            _require(
                self._temporary is not None
                and set(self._identities) == {"root", "home", "config", "state", "cache"}
                and set(self._descriptors) == set(self._identities),
                "isolated GitHub CLI configuration was not initialized",
            )
            directory = pathlib.Path(self._temporary.name)
            _require(
                sorted(os.listdir(directory)) == ["cache", "config", "home", "state"],
                "isolated GitHub CLI root inventory changed",
            )
            for name, path in {
                "root": directory,
                "home": directory / "home",
                "config": directory / "config",
                "state": directory / "state",
                "cache": directory / "cache",
            }.items():
                opened = _github_cli_private_directory_identity(
                    os.fstat(self._descriptors[name])
                )
                named = _github_cli_private_directory_identity(path.lstat())
                _require(
                    opened == self._identities[name] == named,
                    "isolated GitHub CLI directory identity changed",
                )
            _require(
                not os.listdir(directory / "home")
                and not os.listdir(directory / "config"),
                "isolated GitHub CLI configuration changed",
            )
            _validate_isolated_github_tree(directory)
        except (GitHubReleaseObservationError, OSError) as exc:
            integrity_error = _local_integrity_error(
                GitHubCliEnvironmentIntegrityError,
                "isolated GitHub CLI configuration changed during execution",
                preceding,
            )
            integrity_error.__cause__ = exc
        close_error: OSError | None = None
        for descriptor in self._descriptors.values():
            try:
                os.close(descriptor)
            except OSError as exc:
                close_error = close_error or exc
        self._descriptors = {}
        self._identities = {}
        cleanup_error = self._cleanup()
        if integrity_error is not None:
            raise integrity_error
        if close_error is not None:
            raise _local_integrity_error(
                GitHubCliEnvironmentIntegrityError,
                "cannot close the isolated GitHub CLI environment",
                preceding,
            ) from close_error
        if cleanup_error is not None:
            raise _local_integrity_error(
                GitHubCliEnvironmentIntegrityError,
                "cannot remove the isolated GitHub CLI environment",
                preceding,
            ) from cleanup_error
        return False

    def _cleanup(self) -> OSError | None:
        temporary = self._temporary
        self._temporary = None
        if temporary is None:
            return None
        try:
            temporary.cleanup()
        except OSError as exc:
            return exc
        return None


def _validate_isolated_github_tree(root: pathlib.Path) -> None:
    entries = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        relative = pathlib.Path(directory).relative_to(root)
        _require(
            len(relative.parts) <= 6,
            "isolated GitHub CLI tree exceeds its depth bound",
        )
        for name in (*directory_names, *file_names):
            entries += 1
            _require(entries <= 256, "isolated GitHub CLI tree is too large")
            path = pathlib.Path(directory) / name
            metadata = path.lstat()
            _require(
                metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
                and (
                    stat.S_ISDIR(metadata.st_mode)
                    or (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_nlink == 1
                    )
                ),
                "isolated GitHub CLI tree contains an unsafe entry",
            )
            if stat.S_ISREG(metadata.st_mode):
                total_bytes += metadata.st_size
                _require(
                    total_bytes <= 16 * 1024 * 1024,
                    "isolated GitHub CLI tree exceeds its byte bound",
                )


def _isolated_github_cli_environment(
    environment: Mapping[str, str],
) -> _IsolatedGitHubCliEnvironment:
    return _IsolatedGitHubCliEnvironment(environment)


def _validated_github_cli_temp_root() -> str:
    _require(
        isinstance(GITHUB_CLI_TEMP_ROOT, pathlib.Path)
        and GITHUB_CLI_TEMP_ROOT.is_absolute(),
        "fixed GitHub CLI temporary root must be an absolute path",
    )
    try:
        root = GITHUB_CLI_TEMP_ROOT.resolve(strict=True)
        metadata = root.stat()
    except OSError as exc:
        raise GitHubReleaseObservationError(
            "cannot resolve the fixed GitHub CLI temporary root"
        ) from exc
    mode = stat.S_IMODE(metadata.st_mode)
    _require(
        root.is_absolute()
        and stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and (
            mode & 0o022 == 0
            or mode & stat.S_ISVTX == stat.S_ISVTX
        ),
        "fixed GitHub CLI temporary root metadata is unsafe",
    )
    return str(root)


def _github_cli_private_directory_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int]:
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_nlink >= 2,
        "isolated GitHub CLI configuration metadata is unsafe",
    )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    )


def _capture_github_api_get(
    tool: GitHubCliIdentity,
    endpoint: str,
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: GitHubCommandRunner,
) -> bytes:
    """Run one fixed-version GitHub REST GET through the shared CLI boundary."""

    return capture_github_cli(
        tool,
        [
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            endpoint,
        ],
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        environment=environment,
        label=label,
        runner=runner,
    )


def parse_stable_tag_rulesets(
    ruleset_list_raw: bytes,
    ruleset_details_raw: Mapping[int, bytes],
) -> StableTagProtectionObservation:
    """Require active, no-bypass update+delete rules for both stable tags."""

    ordered_ids = _parse_stable_tag_ruleset_ids(ruleset_list_raw)
    _require(
        set(ruleset_details_raw) == set(ordered_ids)
        and all(
            type(ruleset_id) is int and isinstance(raw, bytes)
            for ruleset_id, raw in ruleset_details_raw.items()
        ),
        "GitHub tag ruleset detail inventory differs from the list",
    )

    required_rules = frozenset({"update", "deletion"})
    coverage = {tag_ref: set() for tag_ref in PROTECTED_STABLE_TAG_REFS}
    authoritative_ids: set[int] = set()
    for ruleset_id in ordered_ids:
        try:
            detail_value = parse_strict_json_bytes(
                ruleset_details_raw[ruleset_id],
                label=f"GitHub tag ruleset {ruleset_id}",
            )
        except EvidenceIOError as exc:
            raise GitHubReleaseObservationError(
                "GitHub tag ruleset detail is not strict JSON"
            ) from exc
        detail = _object(detail_value, f"GitHub tag ruleset {ruleset_id}")
        _require(
            detail.get("id") == ruleset_id,
            "GitHub tag ruleset detail ID differs from its request",
        )
        conditions = _object(
            detail.get("conditions"),
            f"GitHub tag ruleset {ruleset_id} conditions",
        )
        _exact_keys(
            conditions,
            frozenset({"ref_name"}),
            f"GitHub tag ruleset {ruleset_id} conditions",
        )
        ref_name = _object(
            conditions.get("ref_name"),
            f"GitHub tag ruleset {ruleset_id} ref condition",
        )
        _exact_keys(
            ref_name,
            frozenset({"include", "exclude"}),
            f"GitHub tag ruleset {ruleset_id} ref condition",
        )
        includes = ref_name.get("include")
        excludes = ref_name.get("exclude")
        _require(
            isinstance(includes, list)
            and isinstance(excludes, list)
            and all(
                isinstance(pattern, str)
                and 0 < len(pattern) <= 256
                and "\x00" not in pattern
                for pattern in [*includes, *excludes]
            )
            and len(includes) == len(set(includes))
            and len(excludes) == len(set(excludes)),
            "GitHub tag ruleset ref conditions are malformed",
        )
        explicit_stable_refs = set(includes) & set(PROTECTED_STABLE_TAG_REFS)
        if not explicit_stable_refs:
            continue
        _require(
            detail.get("target") == "tag"
            and detail.get("enforcement") == "active"
            and detail.get("source_type") == "Repository"
            and detail.get("source") == GITHUB_REPOSITORY,
            "GitHub stable tag ruleset target or enforcement differs",
        )
        _require(
            detail.get("bypass_actors") == [],
            "GitHub stable tag ruleset permits bypass or hides bypass state",
        )
        _require(
            excludes == [],
            "GitHub stable tag ruleset has an exclusion",
        )
        rules = detail.get("rules")
        _require(isinstance(rules, list), "GitHub tag ruleset rules must be an array")
        admitted_rules: set[str] = set()
        for rule_index, rule_value in enumerate(rules):
            rule = _object(
                rule_value,
                f"GitHub tag ruleset {ruleset_id} rule {rule_index}",
            )
            rule_type = rule.get("type")
            _require(
                isinstance(rule_type, str) and bool(rule_type),
                "GitHub tag ruleset rule type is malformed",
            )
            if rule_type == "deletion":
                _exact_keys(
                    rule,
                    frozenset({"type"}),
                    "GitHub stable tag deletion rule",
                )
                admitted_rules.add(rule_type)
            elif rule_type == "update":
                # The live tag-target rulesets API stores the update rule
                # without parameters: the branch-only fetch-and-merge
                # concession is stripped on write, so the bare rule is the
                # strict no-update form. The explicit parameters shape is
                # still accepted for older inventories and must pin the
                # concession to False; any other concession value or key
                # remains a refusal.
                if "parameters" in rule:
                    _exact_keys(
                        rule,
                        frozenset({"type", "parameters"}),
                        "GitHub stable tag update rule",
                    )
                    parameters = _object(
                        rule.get("parameters"),
                        "GitHub stable tag update parameters",
                    )
                    _exact_keys(
                        parameters,
                        frozenset({"update_allows_fetch_and_merge"}),
                        "GitHub stable tag update parameters",
                    )
                    _require(
                        parameters.get("update_allows_fetch_and_merge") is False,
                        "GitHub stable tag update rule permits an alternate update",
                    )
                else:
                    _exact_keys(
                        rule,
                        frozenset({"type"}),
                        "GitHub stable tag update rule",
                    )
                admitted_rules.add(rule_type)
        protected_rules = admitted_rules & required_rules
        if protected_rules:
            authoritative_ids.add(ruleset_id)
            for tag_ref in explicit_stable_refs:
                coverage[tag_ref].update(protected_rules)

    _require(
        all(
            coverage[tag_ref] == required_rules
            for tag_ref in PROTECTED_STABLE_TAG_REFS
        ),
        "GitHub stable tags lack active no-bypass update and deletion protection",
    )
    projection = {
        "repository": GITHUB_REPOSITORY,
        "ruleset_ids": sorted(authoritative_ids),
        "tag_refs": list(PROTECTED_STABLE_TAG_REFS),
    }
    return StableTagProtectionObservation(
        repository=GITHUB_REPOSITORY,
        ruleset_ids=tuple(sorted(authoritative_ids)),
        tag_refs=PROTECTED_STABLE_TAG_REFS,
        observation_sha256=hashlib.sha256(canonical_json(projection)).hexdigest(),
    )


def _parse_stable_tag_ruleset_ids(ruleset_list_raw: bytes) -> tuple[int, ...]:
    try:
        value = parse_strict_json_bytes(
            ruleset_list_raw,
            label="GitHub tag ruleset list",
        )
    except EvidenceIOError as exc:
        raise GitHubReleaseObservationError(
            "GitHub tag ruleset list is not strict JSON"
        ) from exc
    _require(isinstance(value, list), "GitHub tag ruleset list must be an array")
    _require(
        len(value) < 100 and len(value) <= MAX_TAG_RULESETS,
        "GitHub tag ruleset list is incomplete or exceeds policy",
    )
    ruleset_ids: list[int] = []
    for index, item in enumerate(value):
        summary = _object(item, f"GitHub tag ruleset summary {index}")
        ruleset_id = summary.get("id")
        _require(
            type(ruleset_id) is int and 1 <= ruleset_id <= MAX_RELEASE_ID,
            "GitHub tag ruleset ID is malformed",
        )
        ruleset_ids.append(ruleset_id)
    _require(
        len(ruleset_ids) == len(set(ruleset_ids)),
        "GitHub tag ruleset list contains duplicate IDs",
    )
    return tuple(sorted(ruleset_ids))


def sample_stable_tag_protection_once(
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagProtectionObservation:
    """Take one complete exact stable-tag ruleset sample."""

    environment = github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = select_github_cli()
    list_endpoint = (
        f"repos/{GITHUB_REPOSITORY}/rulesets?includes_parents=true&"
        "targets=tag&per_page=100&page=1"
    )

    list_raw = _capture_github_api_get(
        tool,
        list_endpoint,
        timeout_seconds=120,
        maximum_bytes=MAX_TAG_RULESET_LIST_BYTES,
        environment=environment,
        label="GitHub stable tag ruleset list",
        runner=runner,
    )
    detail_raw: dict[int, bytes] = {}
    for ruleset_id in _parse_stable_tag_ruleset_ids(list_raw):
        detail_raw[ruleset_id] = _capture_github_api_get(
            tool,
            (
                f"repos/{GITHUB_REPOSITORY}/rulesets/{ruleset_id}"
                "?includes_parents=true"
            ),
            timeout_seconds=120,
            maximum_bytes=MAX_TAG_RULESET_BYTES,
            environment=environment,
            label="GitHub stable tag ruleset detail",
            runner=runner,
        )
    return parse_stable_tag_rulesets(list_raw, detail_raw)


def observe_stable_tag_protection(
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagProtectionObservation:
    """Sample exact stable-tag rules twice through the pinned read-only CLI."""

    before = sample_stable_tag_protection_once(
        source_environment=source_environment, runner=runner
    )
    after = sample_stable_tag_protection_once(
        source_environment=source_environment, runner=runner
    )
    _require(
        before == after,
        "GitHub stable tag protection changed during observation",
    )
    return before


def parse_stable_tag_state(
    reference_raw: Mapping[str, bytes],
    tag_object_raw: Mapping[str, bytes],
    commit_raw: bytes | None,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_tag_objects: Sequence[str] | None = None,
) -> StableTagStateObservation:
    """Parse an exact absent or annotated stable-tag remote state."""

    state, commit, tree, tag_objects = _stable_tag_state_expectation(
        expected_commit,
        expected_tree,
        expected_tag_objects,
    )
    _require(
        set(reference_raw) == set(STABLE_TAG_REFS)
        and all(isinstance(raw, bytes) for raw in reference_raw.values()),
        "GitHub stable tag reference inventory differs",
    )
    references = {
        reference: _parse_matching_stable_tag_reference(
            reference_raw[reference], reference
        )
        for reference in STABLE_TAG_REFS
    }

    if state == "absent":
        _require(
            all(value is None for value in references.values()),
            "GitHub stable tag already exists",
        )
        _require(
            not tag_object_raw and commit_raw is None,
            "absent GitHub stable tag observation includes unexpected objects",
        )
        projection: dict[str, object] = {
            "repository": GITHUB_REPOSITORY,
            "state": state,
            "tag_refs": list(STABLE_TAG_REFS),
        }
        return StableTagStateObservation(
            repository=GITHUB_REPOSITORY,
            state=state,
            tag_refs=STABLE_TAG_REFS,
            tag_objects=(),
            commit=None,
            tree=None,
            observation_sha256=hashlib.sha256(canonical_json(projection)).hexdigest(),
        )

    if commit is None or tree is None or tag_objects is None:
        _fail("exact GitHub stable tag expectation is incomplete")
    observation = _parse_reconciled_stable_tag_state(
        references,
        tag_object_raw,
        commit_raw,
        expected_commit=commit,
        expected_tree=tree,
        expected_tag_objects=tag_objects,
    )
    _require(
        observation.state == "exact",
        "GitHub stable tag set is incomplete",
    )
    return observation


def parse_stable_tag_recovery_state(
    reference_raw: Mapping[str, bytes],
    tag_object_raw: Mapping[str, bytes],
    commit_raw: bytes | None,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_tag_objects: Sequence[str],
) -> StableTagStateObservation:
    """Classify only the safe absent, Apple-only, or exact recovery states."""

    _state, commit, tree, tag_objects = _stable_tag_state_expectation(
        expected_commit,
        expected_tree,
        expected_tag_objects,
    )
    if commit is None or tree is None or tag_objects is None:
        _fail("GitHub stable tag recovery expectation is incomplete")
    _require(
        set(reference_raw) == set(STABLE_TAG_REFS)
        and all(isinstance(raw, bytes) for raw in reference_raw.values()),
        "GitHub stable tag reference inventory differs",
    )
    references = {
        reference: _parse_matching_stable_tag_reference(
            reference_raw[reference], reference
        )
        for reference in STABLE_TAG_REFS
    }
    return _parse_reconciled_stable_tag_state(
        references,
        tag_object_raw,
        commit_raw,
        expected_commit=commit,
        expected_tree=tree,
        expected_tag_objects=tag_objects,
    )


def _parse_reconciled_stable_tag_state(
    references: Mapping[str, str | None],
    tag_object_raw: Mapping[str, bytes],
    commit_raw: bytes | None,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_tag_objects: tuple[str, ...],
) -> StableTagStateObservation:
    observed = tuple(references[reference] for reference in STABLE_TAG_REFS)
    present = tuple(value is not None for value in observed)
    _require(
        present != (False, True),
        "platform stable tag exists without its Apple predecessor",
    )
    for index, value in enumerate(observed):
        if value is not None:
            _require(
                value == expected_tag_objects[index],
                "GitHub stable tag reference differs from its expected annotated object",
            )
    present_objects = tuple(
        expected_tag_objects[index]
        for index, is_present in enumerate(present)
        if is_present
    )
    state = "absent" if not present_objects else (
        "exact" if len(present_objects) == len(STABLE_TAG_REFS) else "apple_only"
    )
    if state == "absent":
        _require(
            not tag_object_raw and commit_raw is None,
            "absent GitHub stable tag observation includes unexpected objects",
        )
        projection: dict[str, object] = {
            "repository": GITHUB_REPOSITORY,
            "state": state,
            "tag_refs": list(STABLE_TAG_REFS),
        }
        return StableTagStateObservation(
            repository=GITHUB_REPOSITORY,
            state=state,
            tag_refs=STABLE_TAG_REFS,
            tag_objects=(),
            commit=None,
            tree=None,
            observation_sha256=hashlib.sha256(canonical_json(projection)).hexdigest(),
        )

    _require(
        set(tag_object_raw) == set(present_objects)
        and all(isinstance(raw, bytes) for raw in tag_object_raw.values())
        and isinstance(commit_raw, bytes),
        "GitHub stable tag object inventory differs",
    )
    for index, reference in enumerate(STABLE_TAG_REFS):
        if not present[index]:
            continue
        _parse_stable_annotated_tag(
            tag_object_raw[expected_tag_objects[index]],
            reference=reference,
            expected_tag_object=expected_tag_objects[index],
            expected_commit=expected_commit,
        )
    if commit_raw is None:
        _fail("GitHub stable commit object is absent")
    _parse_stable_commit(
        commit_raw,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
    )
    projection = {
        "commit": expected_commit,
        "repository": GITHUB_REPOSITORY,
        "state": state,
        "tag_objects": list(present_objects),
        "tag_refs": list(STABLE_TAG_REFS),
        "tree": expected_tree,
    }
    return StableTagStateObservation(
        repository=GITHUB_REPOSITORY,
        state=state,
        tag_refs=STABLE_TAG_REFS,
        tag_objects=present_objects,
        commit=expected_commit,
        tree=expected_tree,
        observation_sha256=hashlib.sha256(canonical_json(projection)).hexdigest(),
    )


def _stable_tag_state_expectation(
    expected_commit: str | None,
    expected_tree: str | None,
    expected_tag_objects: Sequence[str] | None,
) -> tuple[str, str | None, str | None, tuple[str, ...] | None]:
    if (
        expected_commit is None
        and expected_tree is None
        and expected_tag_objects is None
    ):
        return "absent", None, None, None
    _require(
        isinstance(expected_commit, str)
        and HEX_40.fullmatch(expected_commit) is not None
        and isinstance(expected_tree, str)
        and HEX_40.fullmatch(expected_tree) is not None
        and isinstance(expected_tag_objects, Sequence)
        and not isinstance(expected_tag_objects, (str, bytes))
        and len(expected_tag_objects) == len(STABLE_TAG_REFS),
        "exact GitHub stable tag expectation is malformed",
    )
    objects = tuple(expected_tag_objects)
    _require(
        all(isinstance(value, str) and HEX_40.fullmatch(value) is not None for value in objects)
        and len(set(objects)) == len(objects)
        and expected_commit not in objects,
        "exact GitHub stable tag objects are malformed",
    )
    return "exact", expected_commit, expected_tree, objects


def _parse_matching_stable_tag_reference(
    raw: bytes,
    expected_reference: str,
) -> str | None:
    try:
        value = parse_strict_json_bytes(raw, label="GitHub stable tag references")
    except EvidenceIOError as exc:
        raise GitHubReleaseObservationError(
            "GitHub stable tag references are not strict JSON"
        ) from exc
    _require(
        expected_reference in STABLE_TAG_REFS and isinstance(value, list),
        "GitHub stable tag reference response is malformed",
    )
    _require(
        len(value) < 100 and len(value) <= MAX_STABLE_TAG_MATCHES,
        "GitHub stable tag reference response is incomplete or exceeds policy",
    )
    matches: list[str] = []
    api_root = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/git"
    for index, item in enumerate(value):
        reference = _object(item, f"GitHub stable tag reference {index}")
        _exact_keys(
            reference,
            frozenset({"node_id", "object", "ref", "url"}),
            f"GitHub stable tag reference {index}",
        )
        name = reference.get("ref")
        node_id = reference.get("node_id")
        _require(
            isinstance(name, str)
            and name.startswith(expected_reference)
            and len(name) <= 256
            and "\x00" not in name
            and isinstance(node_id, str)
            and node_id.isascii()
            and 0 < len(node_id) <= 512,
            "GitHub stable tag reference identity is malformed",
        )
        target = _object(reference.get("object"), "GitHub stable tag reference object")
        _exact_keys(
            target,
            frozenset({"sha", "type", "url"}),
            "GitHub stable tag reference object",
        )
        target_type = target.get("type")
        target_sha = target.get("sha")
        _require(
            isinstance(target_type, str)
            and target_type in {"blob", "commit", "tag", "tree"}
            and isinstance(target_sha, str)
            and HEX_40.fullmatch(target_sha) is not None
            and reference.get("url") == f"{api_root}/refs/{name.removeprefix('refs/')}"
            and target.get("url") == f"{api_root}/{target_type}s/{target_sha}",
            "GitHub stable tag reference target is malformed",
        )
        if name == expected_reference:
            _require(not matches, "GitHub stable tag reference is duplicated")
            _require(
                target_type == "tag",
                "GitHub stable release tag is not annotated",
            )
            matches.append(target_sha)
    return matches[0] if matches else None


def _parse_stable_annotated_tag(
    raw: bytes,
    *,
    reference: str,
    expected_tag_object: str,
    expected_commit: str,
) -> None:
    value = _parse_strict_json(raw, "GitHub annotated stable tag object")
    tag = _object(value, "GitHub annotated stable tag object")
    _exact_keys(
        tag,
        frozenset(
            {"message", "node_id", "object", "sha", "tag", "tagger", "url", "verification"}
        ),
        "GitHub annotated stable tag object",
    )
    tag_name = reference.removeprefix("refs/tags/")
    api_root = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/git"
    target = _object(tag.get("object"), "GitHub annotated stable tag target")
    _exact_keys(
        target,
        frozenset({"sha", "type", "url"}),
        "GitHub annotated stable tag target",
    )
    _require(
        tag.get("tag") == tag_name
        and tag.get("sha") == expected_tag_object
        and tag.get("url") == f"{api_root}/tags/{expected_tag_object}"
        and target.get("type") == "commit"
        and target.get("sha") == expected_commit
        and target.get("url") == f"{api_root}/commits/{expected_commit}",
        "GitHub annotated stable tag identity or peeled commit differs",
    )


def _parse_stable_commit(
    raw: bytes,
    *,
    expected_commit: str,
    expected_tree: str,
) -> None:
    value = _parse_strict_json(raw, "GitHub stable results commit object")
    commit = _object(value, "GitHub stable results commit object")
    _exact_keys(
        commit,
        frozenset(
            {
                "author",
                "committer",
                "html_url",
                "message",
                "node_id",
                "parents",
                "sha",
                "tree",
                "url",
                "verification",
            }
        ),
        "GitHub stable results commit object",
    )
    api_root = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/git"
    tree = _object(commit.get("tree"), "GitHub stable results commit tree")
    _exact_keys(tree, frozenset({"sha", "url"}), "GitHub stable results commit tree")
    _require(
        commit.get("sha") == expected_commit
        and commit.get("url") == f"{api_root}/commits/{expected_commit}"
        and tree.get("sha") == expected_tree
        and tree.get("url") == f"{api_root}/trees/{expected_tree}",
        "GitHub stable results commit or tree differs",
    )


def sample_stable_tag_state_once(
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_tag_objects: Sequence[str] | None = None,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagStateObservation:
    """Take one complete sample of both exact stable refs and objects."""

    state, commit, tree, tag_objects = _stable_tag_state_expectation(
        expected_commit,
        expected_tree,
        expected_tag_objects,
    )
    environment = github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = select_github_cli()

    reference_raw = {
        reference: _capture_github_api_get(
            tool,
            (
                f"repos/{GITHUB_REPOSITORY}/git/matching-refs/"
                f"{reference.removeprefix('refs/')}?per_page=100&page=1"
            ),
            timeout_seconds=120,
            maximum_bytes=MAX_STABLE_TAG_REFERENCE_BYTES,
            environment=environment,
            label="GitHub stable tag reference observation",
            runner=runner,
        )
        for reference in STABLE_TAG_REFS
    }
    raw_tags: dict[str, bytes] = {}
    raw_commit: bytes | None = None
    if state == "exact":
        if commit is None or tag_objects is None:
            _fail("exact stable tag sample lacks its expected objects")
        raw_tags = {
            tag_object: _capture_github_api_get(
                tool,
                f"repos/{GITHUB_REPOSITORY}/git/tags/{tag_object}",
                timeout_seconds=120,
                maximum_bytes=MAX_STABLE_TAG_OBJECT_BYTES,
                environment=environment,
                label="GitHub annotated stable tag observation",
                runner=runner,
            )
            for tag_object in tag_objects
        }
        raw_commit = _capture_github_api_get(
            tool,
            f"repos/{GITHUB_REPOSITORY}/git/commits/{commit}",
            timeout_seconds=120,
            maximum_bytes=MAX_STABLE_COMMIT_OBJECT_BYTES,
            environment=environment,
            label="GitHub stable results commit observation",
            runner=runner,
        )
    return parse_stable_tag_state(
        reference_raw,
        raw_tags,
        raw_commit,
        expected_commit=commit,
        expected_tree=tree,
        expected_tag_objects=tag_objects,
    )


def observe_stable_tag_state(
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_tag_objects: Sequence[str] | None = None,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagStateObservation:
    """Sample both exact stable refs and their immutable objects twice."""

    before = sample_stable_tag_state_once(
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_tag_objects=expected_tag_objects,
        source_environment=source_environment,
        runner=runner,
    )
    after = sample_stable_tag_state_once(
        expected_commit=expected_commit,
        expected_tree=expected_tree,
        expected_tag_objects=expected_tag_objects,
        source_environment=source_environment,
        runner=runner,
    )
    _require(before == after, "GitHub stable tag state changed during observation")
    return before


def observe_stable_tag_recovery_state(
    expected_commit: str,
    expected_tree: str,
    expected_tag_objects: Sequence[str],
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagStateObservation:
    """Double-sample the only safe states after an uncertain ordered push."""

    _state, commit, tree, tag_objects = _stable_tag_state_expectation(
        expected_commit,
        expected_tree,
        expected_tag_objects,
    )
    if commit is None or tree is None or tag_objects is None:
        _fail("GitHub stable tag recovery expectation is incomplete")
    environment = github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = select_github_cli()

    def sample() -> StableTagStateObservation:
        reference_raw = {
            reference: _capture_github_api_get(
                tool,
                (
                    f"repos/{GITHUB_REPOSITORY}/git/matching-refs/"
                    f"{reference.removeprefix('refs/')}?per_page=100&page=1"
                ),
                timeout_seconds=120,
                maximum_bytes=MAX_STABLE_TAG_REFERENCE_BYTES,
                environment=environment,
                label="GitHub stable tag recovery reference observation",
                runner=runner,
            )
            for reference in STABLE_TAG_REFS
        }
        references = tuple(
            _parse_matching_stable_tag_reference(
                reference_raw[reference], reference
            )
            for reference in STABLE_TAG_REFS
        )
        _require(
            tuple(value is not None for value in references) != (False, True),
            "platform stable tag exists without its Apple predecessor",
        )
        present_objects: list[str] = []
        for index, value in enumerate(references):
            if value is not None:
                _require(
                    value == tag_objects[index],
                    "GitHub stable tag reference differs from its expected annotated object",
                )
                present_objects.append(tag_objects[index])
        raw_tags = {
            tag_object: _capture_github_api_get(
                tool,
                f"repos/{GITHUB_REPOSITORY}/git/tags/{tag_object}",
                timeout_seconds=120,
                maximum_bytes=MAX_STABLE_TAG_OBJECT_BYTES,
                environment=environment,
                label="GitHub annotated stable tag recovery observation",
                runner=runner,
            )
            for tag_object in present_objects
        }
        raw_commit = None
        if present_objects:
            raw_commit = _capture_github_api_get(
                tool,
                f"repos/{GITHUB_REPOSITORY}/git/commits/{commit}",
                timeout_seconds=120,
                maximum_bytes=MAX_STABLE_COMMIT_OBJECT_BYTES,
                environment=environment,
                label="GitHub stable recovery commit observation",
                runner=runner,
            )
        return parse_stable_tag_recovery_state(
            reference_raw,
            raw_tags,
            raw_commit,
            expected_commit=commit,
            expected_tree=tree,
            expected_tag_objects=tag_objects,
        )

    before = sample()
    after = sample()
    _require(
        before == after,
        "GitHub stable tag recovery state changed during observation",
    )
    return before


def _main(arguments: Sequence[str]) -> int:
    supplied = list(arguments)
    if supplied == ["verify-stable-tag-protection"]:
        observation = observe_stable_tag_protection()
        print(
            "STABLE_TAG_PROTECTION_PASS "
            f"repository={observation.repository} "
            f"rulesets={','.join(str(value) for value in observation.ruleset_ids)} "
            f"observation_sha256={observation.observation_sha256}"
        )
        return 0
    if supplied == ["stable-tag-state", "absent"]:
        tag_state = observe_stable_tag_state()
    elif len(supplied) == 6 and supplied[:2] == ["stable-tag-state", "exact"]:
        tag_state = observe_stable_tag_state(
            expected_commit=supplied[2],
            expected_tree=supplied[3],
            expected_tag_objects=(supplied[4], supplied[5]),
        )
    elif len(supplied) == 6 and supplied[:2] == ["stable-tag-state", "recover"]:
        tag_state = observe_stable_tag_recovery_state(
            supplied[2],
            supplied[3],
            (supplied[4], supplied[5]),
        )
    else:
        print(
            "error: usage: github_release_observation.py "
            "verify-stable-tag-protection | stable-tag-state absent | "
            "stable-tag-state exact R TREE APPLE_TAG_OBJECT PLATFORM_TAG_OBJECT | "
            "stable-tag-state recover R TREE APPLE_TAG_OBJECT PLATFORM_TAG_OBJECT",
            file=sys.stderr,
        )
        return 2
    print(
        "STABLE_TAG_STATE_PASS "
        f"repository={tag_state.repository} state={tag_state.state} "
        f"observation_sha256={tag_state.observation_sha256}"
    )
    return 0


def _github_cli_argv(
    tool: GitHubCliIdentity,
    arguments: Sequence[str],
) -> list[str]:
    _require(
        isinstance(tool, GitHubCliIdentity)
        and isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and bool(arguments)
        and all(
            isinstance(argument, str) and argument and "\x00" not in argument
            for argument in arguments
        ),
        "GitHub command arguments are malformed",
    )
    return [tool.path, *arguments]


def _execute_github_cli(
    tool: GitHubCliIdentity,
    invoke: Callable[[], BoundedResult],
    *,
    label: str,
) -> BoundedResult:
    resample_github_cli(tool)
    result: BoundedResult | None = None
    execution_error: BaseException | None = None
    try:
        result = invoke()
        if not isinstance(result, BoundedResult) or type(result.returncode) is not int:
            execution_error = GitHubReleaseObservationError(
                f"{label} result type differs"
            )
        elif result.returncode != 0:
            execution_error = GitHubCliExecutionError(
                label,
                error_kind=None,
                returncode=result.returncode,
            )
    except BoundedProcessError as exc:
        if exc.cleanup_ambiguous:
            execution_error = GitHubProcessOwnershipIntegrityError(
                f"{label} subprocess cleanup is indeterminate",
                error_kind=exc.kind,
                signal_number=exc.signal_number,
            )
        else:
            execution_error = GitHubCliExecutionError(
                label,
                error_kind=exc.kind,
                returncode=None,
            )
    except GitHubReleaseObservationError as exc:
        execution_error = exc
    except Exception:
        execution_error = GitHubReleaseObservationError(
            f"{label} failed safely"
        )
    except BaseException as exc:
        execution_error = exc
    try:
        resample_github_cli(tool)
    except GitHubCliIdentityIntegrityError as exc:
        raise _local_integrity_error(
            GitHubCliIdentityIntegrityError,
            f"{label} GitHub CLI identity or bytes changed across execution",
            execution_error,
        ) from exc
    if execution_error is not None:
        raise execution_error
    _require(isinstance(result, BoundedResult), f"{label} result type differs")
    return result


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
        type(policy.expected_prerelease) is bool,
        "GitHub release prerelease policy is not boolean",
    )
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
    """Parse one exact immutable release view and canonical asset projection."""

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
        and view["isPrerelease"] is policy.expected_prerelease,
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
            and SIMPLE_MEDIA_TYPE.fullmatch(content_type) is not None,
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
        "prerelease": policy.expected_prerelease,
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


def parse_release_list(
    data: bytes,
    *,
    target_tags: tuple[str, str],
    label: str = "GitHub bounded release list",
) -> ReleaseListObservation:
    """Parse a first page and reject the full-page truncation boundary."""

    value = _parse_strict_json(data, label)
    _require(isinstance(value, list), f"{label} must be a JSON array")
    _require(len(value) < 100, f"{label} may be pagination-truncated")
    _require(
        len(target_tags) == 2
        and len(set(target_tags)) == 2
        and all(isinstance(tag, str) and tag for tag in target_tags),
        f"{label} target policy is malformed",
    )
    observed: dict[str, ReleaseListTarget] = {}
    latest_tags: list[str] = []
    for index, raw in enumerate(value):
        item = _object(raw, f"{label} item {index}")
        _exact_keys(item, RELEASE_LIST_KEYS, f"{label} item {index}")
        _require(
            type(item["isDraft"]) is bool
            and type(item["isImmutable"]) is bool
            and type(item["isLatest"]) is bool
            and type(item["isPrerelease"]) is bool
            and isinstance(item["name"], str)
            and isinstance(item["tagName"], str),
            f"{label} item {index} fields are malformed",
        )
        parse_utc_timestamp(item["createdAt"], f"{label} item {index} createdAt")
        if item["publishedAt"] is not None:
            parse_utc_timestamp(
                item["publishedAt"], f"{label} item {index} publishedAt"
            )
        tag = item["tagName"]
        if item["isLatest"]:
            latest_tags.append(tag)
        if tag in target_tags:
            _require(tag not in observed, f"{label} contains a duplicate target tag")
            _require(
                item["isPrerelease"] is False,
                f"{label} target prerelease state differs",
            )
            observed[tag] = ReleaseListTarget(
                tag=tag,
                title=item["name"],
                draft=item["isDraft"],
                immutable=item["isImmutable"],
                latest=item["isLatest"],
                prerelease=item["isPrerelease"],
                published_at=item["publishedAt"],
            )
    _require(
        len(latest_tags) <= 1,
        f"{label} contains multiple latest releases",
    )
    ordered = tuple(observed[tag] for tag in target_tags if tag in observed)
    projection = {
        "latest_tag": None if not latest_tags else latest_tags[0],
        "targets": [dataclasses.asdict(target) for target in ordered],
    }
    return ReleaseListObservation(
        targets=ordered,
        latest_tag=None if not latest_tags else latest_tags[0],
        canonical=canonical_json(projection),
    )


def _validate_mutable_release_policy(policy: MutableReleasePolicy) -> None:
    _require(
        isinstance(policy, MutableReleasePolicy)
        and policy.repository == GITHUB_REPOSITORY,
        "mutable GitHub release repository differs",
    )
    _sha1(policy.tag_commit, "mutable GitHub release tag commit")
    _require(
        isinstance(policy.tag, str)
        and policy.tag
        and isinstance(policy.title, str)
        and 0 < len(policy.title) <= 256
        and isinstance(policy.body, str)
        and 0 < len(policy.body) <= 16_384
        and "\x00" not in policy.title + policy.body,
        "mutable GitHub release text policy is malformed",
    )
    names = policy.asset_names
    expected_names = frozenset(names)
    _require(
        bool(names)
        and len(names) == len(expected_names)
        and all(SAFE_ASSET_NAME.fullmatch(name) for name in names)
        and frozenset(policy.expected_sha256) == expected_names
        and frozenset(policy.expected_sizes) == expected_names
        and frozenset(policy.expected_content_types) == expected_names,
        "mutable GitHub release asset policy differs",
    )
    for name in names:
        _sha256(policy.expected_sha256[name], f"mutable asset digest for {name}")
        _positive_integer(policy.expected_sizes[name], f"mutable asset size for {name}")
        content_type = policy.expected_content_types[name]
        _require(
            isinstance(content_type, str)
            and SIMPLE_MEDIA_TYPE.fullmatch(content_type) is not None,
            f"mutable asset content type differs for {name}",
        )


def validate_mutable_release_policy(policy: MutableReleasePolicy) -> None:
    """Validate the public mutable-release policy boundary."""

    _validate_mutable_release_policy(policy)


def parse_mutable_release_view(
    data: bytes,
    *,
    policy: MutableReleasePolicy,
    is_latest: bool,
    label: str = "GitHub mutable release view",
) -> MutableReleaseView:
    """Parse one exact draft-or-immutable release and ordered asset prefix."""

    _validate_mutable_release_policy(policy)
    value = _parse_strict_json(data, label)
    view = _object(value, label)
    _exact_keys(view, MUTABLE_RELEASE_VIEW_KEYS, label)
    release_id = _positive_integer(view["databaseId"], f"{label} release ID")
    _require(
        type(view["isDraft"]) is bool
        and type(view["isImmutable"]) is bool
        and view["isPrerelease"] is False
        and type(is_latest) is bool,
        f"{label} publication flags differ",
    )
    _require(
        view["tagName"] == policy.tag
        and view["targetCommitish"] in {"main", policy.tag_commit}
        and view["name"] == policy.title
        and view["body"] == policy.body,
        f"{label} identity or text differs",
    )
    repository_url = f"https://github.com/{policy.repository}"
    # A draft release is not yet keyed to its tag ref: GitHub reports the release
    # html url -- and every asset browser_download_url -- under a synthetic
    # "untagged-<hex>" slug, flipping to the tag form only once the release is
    # published. Derive the effective download slug from the observed release url
    # so the release and its assets are validated against the same GitHub keying;
    # the strict tag form is required for the published (non-draft) shape.
    observed_release_url = view["url"]
    if view["isDraft"]:
        draft_url_match = re.fullmatch(
            rf"{re.escape(repository_url)}/releases/tag/(untagged-[0-9a-f]+)",
            observed_release_url if isinstance(observed_release_url, str) else "",
        )
        _require(
            draft_url_match is not None,
            f"{label} draft release URL differs",
        )
        download_slug = draft_url_match.group(1)
    else:
        _require(
            observed_release_url == f"{repository_url}/releases/tag/{policy.tag}",
            f"{label} release URL differs",
        )
        download_slug = policy.tag
    _require(
        view["apiUrl"]
        == f"https://api.github.com/repos/{policy.repository}/releases/{release_id}"
        and view["uploadUrl"]
        == (
            f"https://uploads.github.com/repos/{policy.repository}/releases/"
            f"{release_id}/assets{{?name,label}}"
        ),
        f"{label} URLs differ",
    )
    if view["isDraft"]:
        _require(
            view["isImmutable"] is False
            and view["publishedAt"] is None
            and is_latest is False,
            f"{label} draft state differs",
        )
        published_at: str | None = None
    else:
        _require(
            view["isImmutable"] is True and view["publishedAt"] is not None,
            f"{label} published release is not immutable",
        )
        published_at = view["publishedAt"]
        parse_utc_timestamp(published_at, f"{label} publishedAt")
    raw_assets = view["assets"]
    _require(isinstance(raw_assets, list), f"{label} assets must be an array")
    _require(
        len(raw_assets) <= len(policy.asset_names),
        f"{label} has extra assets",
    )
    raw_by_name: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_assets):
        asset = _object(raw, f"{label} asset {index}")
        _exact_keys(asset, ASSET_VIEW_KEYS, f"{label} asset {index}")
        observed_name = asset["name"]
        _require(
            isinstance(observed_name, str)
            and observed_name in policy.asset_names
            and observed_name not in raw_by_name,
            f"{label} asset name or uniqueness differs",
        )
        raw_by_name[observed_name] = asset
    prefix_names = policy.asset_names[: len(raw_assets)]
    _require(
        frozenset(raw_by_name) == frozenset(prefix_names),
        f"{label} assets are not the exact planned prefix",
    )
    parsed: list[MutableReleaseAsset] = []
    observed_asset_ids: set[int] = set()
    observed_node_ids: set[str] = set()
    for index, name in enumerate(prefix_names):
        asset = raw_by_name[name]
        state = asset["state"]
        _require(
            state != "starter",
            f"{label} contains a starter asset requiring independent deletion approval",
        )
        _require(state == "uploaded", f"{label} asset state differs")
        size = _nonnegative_integer(asset["size"], f"{label} asset size for {name}")
        digest_value = asset["digest"]
        _require(
            isinstance(digest_value, str)
            and digest_value.startswith("sha256:"),
            f"{label} asset digest differs for {name}",
        )
        digest = _sha256(
            digest_value.removeprefix("sha256:"),
            f"{label} asset digest for {name}",
        )
        _require(
            size == policy.expected_sizes[name]
            and digest == policy.expected_sha256[name]
            and isinstance(asset["contentType"], str)
            and asset["contentType"] == policy.expected_content_types[name],
            f"{label} uploaded asset binding differs for {name}",
        )
        api_url = asset["apiUrl"]
        _require(
            asset["label"] == ""
            and asset["url"]
            == f"{repository_url}/releases/download/{download_slug}/{name}"
            and isinstance(api_url, str)
            and re.fullmatch(
                rf"https://api\.github\.com/repos/{re.escape(policy.repository)}/"
                r"releases/assets/[1-9][0-9]*",
                api_url,
            )
            is not None,
            f"{label} asset URLs or label differ for {name}",
        )
        if not isinstance(api_url, str):
            _fail(f"{label} asset API URL is malformed for {name}")
        asset_id_text = api_url.rsplit("/", 1)[-1]
        _require(
            1 <= len(asset_id_text) <= 19
            and all("0" <= character <= "9" for character in asset_id_text)
            and not (len(asset_id_text) > 1 and asset_id_text.startswith("0")),
            f"{label} asset API ID is malformed for {name}",
        )
        asset_id = _positive_integer(
            int(asset_id_text),
            f"{label} asset API ID for {name}",
        )
        _require(
            isinstance(asset["id"], str)
            and len(asset["id"]) <= 256
            and SAFE_NODE_ID.fullmatch(asset["id"]) is not None,
            f"{label} asset node ID differs for {name}",
        )
        _require(
            asset_id not in observed_asset_ids
            and asset["id"] not in observed_node_ids,
            f"{label} asset API or node identity is duplicated",
        )
        observed_asset_ids.add(asset_id)
        observed_node_ids.add(asset["id"])
        _nonnegative_integer(
            asset["downloadCount"], f"{label} asset download count for {name}"
        )
        created_at = parse_utc_timestamp(
            asset["createdAt"], f"{label} asset createdAt for {name}"
        )
        updated_at = parse_utc_timestamp(
            asset["updatedAt"], f"{label} asset updatedAt for {name}"
        )
        _require(
            created_at <= updated_at
            and (
                published_at is None
                or updated_at <= parse_utc_timestamp(
                    published_at, f"{label} publishedAt"
                )
            ),
            f"{label} asset timestamps are out of order for {name}",
        )
        parsed.append(
            MutableReleaseAsset(
                asset_id=asset_id,
                node_id=asset["id"],
                name=name,
                size=size,
                sha256=digest,
                content_type=asset["contentType"],
                state=state,
                created_at=asset["createdAt"],
                updated_at=asset["updatedAt"],
            )
        )
    stable = {
        "assets": [dataclasses.asdict(asset) for asset in parsed],
        "body": policy.body,
        "draft": view["isDraft"],
        "immutable": view["isImmutable"],
        "is_latest": is_latest,
        "prerelease": False,
        "published_at": published_at,
        "release_id": release_id,
        "tag": policy.tag,
        "target_commitish": view["targetCommitish"],
        "title": policy.title,
    }
    return MutableReleaseView(
        release_id=release_id,
        tag=policy.tag,
        draft=view["isDraft"],
        immutable=view["isImmutable"],
        prerelease=False,
        is_latest=is_latest,
        published_at=published_at,
        assets=tuple(parsed),
        canonical=canonical_json(stable),
    )


def _observe_mutable_release_transaction_once(
    policies: tuple[MutableReleasePolicy, MutableReleasePolicy],
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> MutableReleaseTransactionObservation:
    """Observe the two target releases, immutable setting, and latest tag."""

    _require(
        len(policies) == 2 and policies[0].tag != policies[1].tag,
        "mutable release transaction policy differs",
    )
    for policy in policies:
        _validate_mutable_release_policy(policy)
    environment = github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = select_github_cli()
    list_arguments = (
        "release",
        "list",
        "--repo",
        f"github.com/{GITHUB_REPOSITORY}",
        "--limit",
        "100",
        "--json",
        ",".join(RELEASE_LIST_FIELDS),
    )

    def capture(arguments: Sequence[str], *, maximum: int, label: str) -> bytes:
        return capture_github_cli(
            tool,
            arguments,
            timeout_seconds=120,
            maximum_bytes=maximum,
            environment=environment,
            label=label,
            runner=runner,
        )

    list_before = capture(
        list_arguments,
        maximum=4 * 1024 * 1024,
        label="GitHub stable release list before views",
    )
    listed = parse_release_list(
        list_before,
        target_tags=(policies[0].tag, policies[1].tag),
    )
    repository_raw = capture(
        (
            "repo",
            "view",
            f"github.com/{GITHUB_REPOSITORY}",
            "--json",
            ",".join(REPOSITORY_VIEW_FIELDS),
        ),
        maximum=1024 * 1024,
        label="GitHub stable publication repository view",
    )
    repository_view = parse_repository_view(
        repository_raw,
        policy=RepositoryPolicy(
            repository=GITHUB_REPOSITORY,
            repository_url=f"https://github.com/{GITHUB_REPOSITORY}",
        ),
        label="GitHub stable publication repository view",
    )
    immutable_raw = capture(
        (
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
            "--jq",
            "{enabled: .enabled, enforced_by_owner: .enforced_by_owner}",
            f"repos/{GITHUB_REPOSITORY}/immutable-releases",
        ),
        maximum=1024,
        label="GitHub immutable release setting",
    )
    immutable_value = _parse_strict_json(
        immutable_raw, "GitHub immutable release setting"
    )
    immutable = _object(immutable_value, "GitHub immutable release setting")
    _exact_keys(
        immutable,
        frozenset({"enabled", "enforced_by_owner"}),
        "GitHub immutable release setting",
    )
    _require(
        immutable["enabled"] is True
        and type(immutable["enforced_by_owner"]) is bool,
        "GitHub immutable releases are not enabled",
    )
    if listed.latest_tag is not None:
        latest_raw = capture(
            (
                "api",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                "--jq",
                "{tagName: .tag_name}",
                f"repos/{GITHUB_REPOSITORY}/releases/latest",
            ),
            maximum=1024,
            label="GitHub latest release",
        )
        latest_value = _object(
            _parse_strict_json(latest_raw, "GitHub latest release"),
            "GitHub latest release",
        )
        _exact_keys(
            latest_value,
            frozenset({"tagName"}),
            "GitHub latest release",
        )
        _require(
            latest_value["tagName"] == listed.latest_tag,
            "GitHub latest endpoint differs from the complete release list",
        )
    listed_by_tag = {target.tag: target for target in listed.targets}
    releases: list[MutableReleaseView | None] = []
    for policy in policies:
        if policy.tag not in listed_by_tag:
            releases.append(None)
            continue
        summary = listed_by_tag[policy.tag]
        view_raw = capture(
            (
                "release",
                "view",
                policy.tag,
                "--repo",
                f"github.com/{GITHUB_REPOSITORY}",
                "--json",
                ",".join(MUTABLE_RELEASE_VIEW_FIELDS),
            ),
            maximum=8 * 1024 * 1024,
            label=f"GitHub target release view for {policy.tag}",
        )
        raw_view = _object(
            _parse_strict_json(view_raw, f"GitHub target release view for {policy.tag}"),
            f"GitHub target release view for {policy.tag}",
        )
        _exact_keys(
            raw_view,
            MUTABLE_RELEASE_VIEW_KEYS,
            f"GitHub target release view for {policy.tag}",
        )
        release_id = _positive_integer(
            raw_view["databaseId"], f"GitHub target release ID for {policy.tag}"
        )
        asset_raw = capture(
            (
                "api",
                "--method",
                "GET",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                f"X-GitHub-Api-Version: {GITHUB_API_VERSION}",
                "--jq",
                (
                    "[.[] | {apiUrl: .url, contentType: .content_type, "
                    "createdAt: .created_at, digest: .digest, "
                    "downloadCount: .download_count, id: .node_id, "
                    "label: (.label // \"\"), name: .name, size: .size, "
                    "state: .state, updatedAt: .updated_at, "
                    "url: .browser_download_url}]"
                ),
                (
                    f"repos/{GITHUB_REPOSITORY}/releases/{release_id}/assets"
                    "?per_page=100&page=1"
                ),
            ),
            maximum=8 * 1024 * 1024,
            label=f"GitHub target release assets for {policy.tag}",
        )
        asset_value = _parse_strict_json(
            asset_raw, f"GitHub target release assets for {policy.tag}"
        )
        _require(
            isinstance(asset_value, list) and len(asset_value) < 100,
            f"GitHub target release asset list for {policy.tag} is incomplete",
        )
        embedded = parse_mutable_release_view(
            view_raw,
            policy=policy,
            is_latest=summary.latest,
            label=f"GitHub embedded target release view for {policy.tag}",
        )
        raw_view["assets"] = asset_value
        complete = parse_mutable_release_view(
            canonical_json(raw_view),
            policy=policy,
            is_latest=summary.latest,
            label=f"GitHub complete target release view for {policy.tag}",
        )
        _require(
            embedded.canonical == complete.canonical,
            f"GitHub target release embedded assets differ for {policy.tag}",
        )
        _require(
            summary.title == policy.title
            and summary.draft == complete.draft
            and summary.immutable == complete.immutable
            and summary.prerelease == complete.prerelease
            and summary.published_at == complete.published_at,
            f"GitHub target release list/detail differs for {policy.tag}",
        )
        releases.append(complete)
    observed_asset_ids = [
        asset.asset_id
        for release in releases
        if release is not None
        for asset in release.assets
    ]
    observed_node_ids = [
        asset.node_id
        for release in releases
        if release is not None
        for asset in release.assets
    ]
    _require(
        len(observed_asset_ids) == len(set(observed_asset_ids))
        and len(observed_node_ids) == len(set(observed_node_ids)),
        "GitHub target releases reuse an asset API or node identity",
    )
    list_after = capture(
        list_arguments,
        maximum=4 * 1024 * 1024,
        label="GitHub stable release list after views",
    )
    _require(
        list_after == list_before,
        "GitHub stable release list changed during observation",
    )
    release_projections: list[dict[str, Any] | None] = []
    for index, release in enumerate(releases):
        if release is None:
            release_projections.append(None)
            continue
        label = f"GitHub canonical target release {index}"
        release_projections.append(
            _object(_parse_strict_json(release.canonical, label), label)
        )
    projection = {
        "repository_sha256": hashlib.sha256(
            repository_view.canonical
        ).hexdigest(),
        "immutable_enabled": True,
        "immutable_enforced_by_owner": immutable["enforced_by_owner"],
        "latest_tag": listed.latest_tag,
        "releases": release_projections,
    }
    return MutableReleaseTransactionObservation(
        repository_canonical=repository_view.canonical,
        immutable_enabled=True,
        immutable_enforced_by_owner=immutable["enforced_by_owner"],
        latest_tag=listed.latest_tag,
        releases=(releases[0], releases[1]),
        canonical=canonical_json(projection),
    )


def observe_mutable_release_transaction(
    policies: tuple[MutableReleasePolicy, MutableReleasePolicy],
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> MutableReleaseTransactionObservation:
    """Return two byte-identical complete remote release samples."""

    before = _observe_mutable_release_transaction_once(
        policies,
        source_environment=source_environment,
        runner=runner,
    )
    after = _observe_mutable_release_transaction_once(
        policies,
        source_environment=source_environment,
        runner=runner,
    )
    _require(
        before == after,
        "GitHub mutable release transaction changed between complete samples",
    )
    return before


def sample_mutable_release_transaction_once(
    policies: tuple[MutableReleasePolicy, MutableReleasePolicy],
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> MutableReleaseTransactionObservation:
    """Expose one complete sample for a higher-level composite sampler."""

    return _observe_mutable_release_transaction_once(
        policies,
        source_environment=source_environment,
        runner=runner,
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


if __name__ == "__main__":
    try:
        raise SystemExit(_main(sys.argv[1:]))
    except GitHubReleaseObservationError as exc:
        raise SystemExit(f"error: {exc}") from None
