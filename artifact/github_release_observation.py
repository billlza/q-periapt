#!/usr/bin/env python3
"""Domain-neutral policy for one immutable GitHub release observation.

The module owns the single pinned GitHub CLI execution boundary and the pure
parsers for its already-bounded output.  Callers retain private raw bytes and
construct domain receipts only after these shared policy checks pass.
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
    "refs/tags/v0.1.0",
    "refs/tags/abi2-platforms-v0.1.0",
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


def select_github_cli() -> GitHubCliIdentity:
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
    assert observed is not None
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


def resample_github_cli(expected: GitHubCliIdentity) -> None:
    """Reject path, metadata, inode, size, or byte drift from startup."""

    if not isinstance(expected, GitHubCliIdentity):
        _fail("pinned GitHub CLI identity is malformed")
    try:
        observed = select_github_cli()
    except GitHubReleaseObservationError:
        _fail("pinned GitHub CLI identity or bytes changed during observation")
    _require(
        observed == expected,
        "pinned GitHub CLI identity or bytes changed during observation",
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


class _IsolatedGitHubCliEnvironment:
    """Own one empty gh config directory for exactly one command."""

    def __init__(self, environment: Mapping[str, str]) -> None:
        self._environment = _validated_github_cli_environment(environment)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._identity: tuple[int, int, int, int, int] | None = None

    def __enter__(self) -> dict[str, str]:
        root = _validated_github_cli_temp_root()
        try:
            self._temporary = tempfile.TemporaryDirectory(
                prefix="qperiapt-gh-config-",
                dir=root,
            )
            directory = pathlib.Path(self._temporary.name)
            os.chmod(directory, 0o700)
            metadata = directory.lstat()
            self._identity = _github_cli_config_identity(metadata)
            _require(
                not os.listdir(directory),
                "isolated GitHub CLI configuration is not empty",
            )
        except (GitHubReleaseObservationError, OSError) as exc:
            self._cleanup()
            raise GitHubReleaseObservationError(
                "cannot create the isolated GitHub CLI configuration"
            ) from exc
        return {
            **self._environment,
            "GH_CONFIG_DIR": str(directory),
        }

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> bool:
        del exception_type, exception, traceback
        integrity_error: GitHubReleaseObservationError | None = None
        try:
            _require(
                self._temporary is not None and self._identity is not None,
                "isolated GitHub CLI configuration was not initialized",
            )
            directory = pathlib.Path(self._temporary.name)
            metadata = directory.lstat()
            _require(
                _github_cli_config_identity(metadata) == self._identity
                and not os.listdir(directory),
                "isolated GitHub CLI configuration changed during observation",
            )
        except (GitHubReleaseObservationError, OSError) as exc:
            integrity_error = GitHubReleaseObservationError(
                "isolated GitHub CLI configuration changed during observation"
            )
            integrity_error.__cause__ = exc
        cleanup_error = self._cleanup()
        if integrity_error is not None:
            raise integrity_error
        if cleanup_error is not None:
            raise GitHubReleaseObservationError(
                "cannot remove the isolated GitHub CLI configuration"
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


def _github_cli_config_identity(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int]:
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and metadata.st_nlink == 2,
        "isolated GitHub CLI configuration metadata is unsafe",
    )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
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
    coverage = {tag_ref: set() for tag_ref in STABLE_TAG_REFS}
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
        explicit_stable_refs = set(includes) & set(STABLE_TAG_REFS)
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
                admitted_rules.add(rule_type)
        protected_rules = admitted_rules & required_rules
        if protected_rules:
            authoritative_ids.add(ruleset_id)
            for tag_ref in explicit_stable_refs:
                coverage[tag_ref].update(protected_rules)

    _require(
        all(coverage[tag_ref] == required_rules for tag_ref in STABLE_TAG_REFS),
        "GitHub stable tags lack active no-bypass update and deletion protection",
    )
    projection = {
        "repository": GITHUB_REPOSITORY,
        "ruleset_ids": sorted(authoritative_ids),
        "tag_refs": list(STABLE_TAG_REFS),
    }
    return StableTagProtectionObservation(
        repository=GITHUB_REPOSITORY,
        ruleset_ids=tuple(sorted(authoritative_ids)),
        tag_refs=STABLE_TAG_REFS,
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


def observe_stable_tag_protection(
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagProtectionObservation:
    """Sample exact stable-tag rules twice through the pinned read-only CLI."""

    environment = github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    tool = select_github_cli()
    list_endpoint = (
        f"repos/{GITHUB_REPOSITORY}/rulesets?includes_parents=true&"
        "targets=tag&per_page=100&page=1"
    )

    def sample() -> StableTagProtectionObservation:
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

    before = sample()
    after = sample()
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

    assert commit is not None and tree is not None and tag_objects is not None
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
    assert commit is not None and tree is not None and tag_objects is not None
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
    assert commit_raw is not None
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
        len(value) <= MAX_STABLE_TAG_MATCHES,
        "GitHub stable tag reference response exceeds policy",
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


def observe_stable_tag_state(
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_tag_objects: Sequence[str] | None = None,
    source_environment: Mapping[str, str] | None = None,
    runner: GitHubCommandRunner = capture_stdout,
) -> StableTagStateObservation:
    """Sample both exact stable refs and their immutable objects twice."""

    state, commit, tree, tag_objects = _stable_tag_state_expectation(
        expected_commit,
        expected_tree,
        expected_tag_objects,
    )
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
                    f"{reference.removeprefix('refs/')}"
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
            assert commit is not None and tag_objects is not None
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

    before = sample()
    after = sample()
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
    assert commit is not None and tree is not None and tag_objects is not None
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
                    f"{reference.removeprefix('refs/')}"
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
    try:
        result = invoke()
    except BoundedProcessError as exc:
        raise GitHubCliExecutionError(
            label,
            error_kind=exc.kind,
            returncode=None,
        ) from None
    except Exception:
        raise GitHubReleaseObservationError(f"{label} failed safely") from None
    finally:
        resample_github_cli(tool)
    _require(
        isinstance(result, BoundedResult)
        and type(result.returncode) is int,
        f"{label} result type differs",
    )
    if result.returncode != 0:
        raise GitHubCliExecutionError(
            label,
            error_kind=None,
            returncode=result.returncode,
        )
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
