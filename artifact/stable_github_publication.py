#!/usr/bin/env python3
"""Coordinate the only Apple+platform GitHub stable release transaction.

The coordinator stages the exact bytes selected by the installed pending
results commit, then admits one irreversible remote mutation at a time.  Every
mutation has a durable no-replace intent and is accepted only after a fresh,
complete, double-sampled GitHub observation.  An ambiguous outcome is never
retried automatically.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import os
import pathlib
import pwd
import re
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, Never, Protocol

import apple_publication_contract as apple_contract
import apple_stable_publication
from bounded_process import BOUNDED_PROCESS_ERROR_KINDS, capture_stdout
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    consume_regular_snapshot_at,
    parse_strict_json_bytes,
)
from git_provenance import (
    GitProvenanceError,
    require_direct_results_only_child,
    run_git_bytes,
    run_git_text,
)
import github_release_observation as github_release
import platform_distribution
import platform_stable_publication_contract as platform_contract
from publication_receipt_io import (
    BoundaryFailureContext,
    PRIVATE_FILE_MODE,
    PrivateDirectoryHandle,
    PrivateFileLockHandle,
    PrivateSafeRootCreatedIdentity,
    PublicationBoundaryIntegrityError,
    PublicationLockHeldError,
    PublicationReceiptIOError,
    canonical_json_bytes,
    create_private_direct_child_handle,
    ensure_private_safe_root,
    ensure_private_safe_root_with_creation,
    exclusive_private_file_lock,
    normalize_safe_root,
    open_pinned_private_file_at,
    open_private_direct_child_handle,
    open_private_directory_at,
    read_fixed_json_snapshot,
    recover_private_staging_residues_at,
    verify_exact_directory_inventory_at,
    verify_private_directory_handle_identity,
    verify_private_file_lock,
    write_private_bytes_noreplace_at,
    write_private_json_noreplace_at,
)
from release_publication_contract import (
    PUBLICATION_STATE_PENDING,
    publication_state,
    stable_source_identity,
)
from release_receipt_finalizer import (
    ReleaseReceiptFinalizerError,
    load_current_results,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
REPOSITORY = github_release.GITHUB_REPOSITORY
PLAN_SCHEMA_VERSION = 1
PLAN_KIND = "qperiapt.stable_github_publication_plan"
JOURNAL_SCHEMA_VERSION = 1
JOURNAL_KIND = "qperiapt.stable_github_publication_journal"
PLAN_LEAF = "publication-plan.json"
PREPARATION_INTENT_LEAF = "preparation-intent.json"
LOCK_LEAF = "publication.lock"
STAGING_DIRECTORY = "staging"
REQUEST_DIRECTORY = "requests"
JOURNAL_DIRECTORY = "journal"
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024
MAX_MUTATION_OUTPUT_BYTES = 1024
JSON_MUTATION_TIMEOUT_SECONDS = 120
ASSET_UPLOAD_TIMEOUT_SECONDS = 300
MAX_ACTIONS = 15
JOURNAL_LEAF = re.compile(
    r"^([0-9]{6})-(intent|reconciliation|outcome)\.json$"
)
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")

APPLE_TITLE = "Q-Periapt 0.1.3 Apple Distribution"
APPLE_BODY = (
    "Stable ABI 2 Apple XCFramework distribution. Verify all four assets and "
    "the immutable release attestation before use."
)
PLATFORM_TITLE = "Q-Periapt 0.1.3 ABI 2 Platform Distribution"
PLATFORM_BODY = (
    "Stable ABI 2 Android and Linux distribution. Verify all seven assets and "
    "the immutable release attestation before use."
)
ACK_DRAFT_BARRIER = "I_ACKNOWLEDGE_BOTH_DRAFTS_BEFORE_ASSET_UPLOAD"
ACK_PUBLICATION_ORDER = "I_ACKNOWLEDGE_APPLE_THEN_PLATFORM_PUBLICATION"
BOUNDARY = (
    "One coordinated stable GitHub release transaction. It binds pending results "
    "P, source S, results-only tag commit R and tree, two annotated tag objects, "
    "four Apple and seven platform assets, fixed release text and API policy. "
    "It never deletes, replaces, clobbers, or retries an ambiguous mutation."
)


class StableGitHubPublicationError(ValueError):
    """The coordinated stable GitHub release transaction is invalid."""


class StableGitHubPublicationOutcomeUnknown(StableGitHubPublicationError):
    """A remote mutation may have taken effect and must not be retried."""


class StableGitHubPublicationLockHeld(StableGitHubPublicationError):
    """Another process owns the account-wide publication lane."""


class StableGitHubPublicationBoundaryIntegrityError(
    StableGitHubPublicationError
):
    """A local lock, plan, staging, or subprocess boundary became unsafe."""

    def __init__(
        self,
        message: str,
        *,
        preceding_error: BaseException | None = None,
        prior_execution_error: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        boundary_context = BoundaryFailureContext.from_exception(preceding_error)
        execution_context = BoundaryFailureContext.from_exception(
            prior_execution_error
        )
        context = BoundaryFailureContext(
            type_name=(
                boundary_context.type_name or execution_context.type_name
            ),
            error_kind=(
                boundary_context.error_kind or execution_context.error_kind
            ),
            returncode=(
                boundary_context.returncode
                if boundary_context.returncode is not None
                else execution_context.returncode
            ),
            signal_number=(
                boundary_context.signal_number
                if boundary_context.signal_number is not None
                else execution_context.signal_number
            ),
            cleanup_ambiguous=(
                boundary_context.cleanup_ambiguous
                or execution_context.cleanup_ambiguous
            ),
        )
        self.preceding_context = context
        self.preceding_type = context.type_name
        self.error_kind = context.error_kind
        self.returncode = context.returncode
        self.signal_number = context.signal_number
        self.cleanup_ambiguous = context.cleanup_ambiguous


def _fail(message: str) -> Never:
    raise StableGitHubPublicationError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _sha1(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_40.fullmatch(value) is not None,
        f"{label} must be one lowercase SHA-1",
    )
    return value


def _sha256(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX_64.fullmatch(value) is not None,
        f"{label} must be one lowercase SHA-256",
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


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be a JSON object with string keys",
    )
    return value


@dataclasses.dataclass(frozen=True, slots=True)
class AssetPlan:
    name: str
    size: int
    sha256: str
    content_type: str
    staging_leaf: str

    def document(self) -> dict[str, object]:
        return {
            "bytes": self.size,
            "content_type": self.content_type,
            "name": self.name,
            "sha256": self.sha256,
            "staging_leaf": self.staging_leaf,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class RequestPlan:
    leaf: str
    size: int
    sha256: str

    def document(self) -> dict[str, object]:
        return {"bytes": self.size, "leaf": self.leaf, "sha256": self.sha256}


@dataclasses.dataclass(frozen=True, slots=True)
class ReleasePlan:
    domain: str
    tag: str
    tag_object: str
    title: str
    body: str
    make_latest: bool
    assets: tuple[AssetPlan, ...]
    create_request: RequestPlan
    publish_request: RequestPlan

    def document(self) -> dict[str, object]:
        return {
            "assets": [asset.document() for asset in self.assets],
            "body": self.body,
            "create_request": self.create_request.document(),
            "domain": self.domain,
            "make_latest": self.make_latest,
            "publish_request": self.publish_request.document(),
            "tag": self.tag,
            "tag_object": self.tag_object,
            "title": self.title,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class PublicationPlan:
    results_sha256: str
    pending_commit: str
    source_parent_commit: str
    tag_commit: str
    tag_tree: str
    canonical_source_tree_sha256: str
    platform_candidate_receipt_sha256: str
    github_cli_sha256: str
    releases: tuple[ReleasePlan, ReleasePlan]

    @property
    def apple(self) -> ReleasePlan:
        return self.releases[0]

    @property
    def platform(self) -> ReleasePlan:
        return self.releases[1]

    def document(self) -> dict[str, object]:
        return {
            "api_version": github_release.GITHUB_API_VERSION,
            "boundary": BOUNDARY,
            "github_cli_sha256": self.github_cli_sha256,
            "kind": PLAN_KIND,
            "releases": [release.document() for release in self.releases],
            "repository": REPOSITORY,
            "results": {
                "commit": self.pending_commit,
                "platform_candidate_receipt_sha256": (
                    self.platform_candidate_receipt_sha256
                ),
                "sha256": self.results_sha256,
            },
            "schema_version": PLAN_SCHEMA_VERSION,
            "source": {
                "source_parent_commit": self.source_parent_commit,
                "tag_commit": self.tag_commit,
                "tag_tree": self.tag_tree,
                "canonical_source_tree_sha256": (
                    self.canonical_source_tree_sha256
                ),
            },
        }

    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.document())).hexdigest()

    def policies(
        self,
    ) -> tuple[
        github_release.MutableReleasePolicy,
        github_release.MutableReleasePolicy,
    ]:
        def policy(release: ReleasePlan) -> github_release.MutableReleasePolicy:
            return github_release.MutableReleasePolicy(
                repository=REPOSITORY,
                tag=release.tag,
                tag_commit=self.tag_commit,
                title=release.title,
                body=release.body,
                asset_names=tuple(asset.name for asset in release.assets),
                expected_sha256={asset.name: asset.sha256 for asset in release.assets},
                expected_sizes={asset.name: asset.size for asset in release.assets},
                expected_content_types={
                    asset.name: asset.content_type for asset in release.assets
                },
            )

        return (policy(self.releases[0]), policy(self.releases[1]))


@dataclasses.dataclass(frozen=True, slots=True)
class RemoteSnapshot:
    releases: github_release.MutableReleaseTransactionObservation
    tag_protection_sha256: str
    tag_state_sha256: str

    def canonical(self) -> bytes:
        return canonical_json_bytes(
            {
                "release_observation_sha256": hashlib.sha256(
                    self.releases.canonical
                ).hexdigest(),
                "tag_protection_sha256": self.tag_protection_sha256,
                "tag_state_sha256": self.tag_state_sha256,
            }
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ClassifiedRemoteState:
    index: int
    name: str


@dataclasses.dataclass(frozen=True, slots=True)
class MutationAction:
    index: int
    action_id: str
    kind: str
    domain: str
    asset_index: int | None = None


RemoteObserver = Callable[[PublicationPlan], RemoteSnapshot]
RemoteMutator = Callable[[PublicationPlan, MutationAction, RemoteSnapshot], None]


_LOCAL_GITHUB_INTEGRITY_ERRORS = (github_release.GitHubLocalIntegrityError,)


def _observe_with_local_integrity_priority(
    observer: RemoteObserver,
    plan: PublicationPlan,
) -> RemoteSnapshot:
    try:
        return observer(plan)
    except _LOCAL_GITHUB_INTEGRITY_ERRORS as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "local GitHub observation boundary integrity failed",
            preceding_error=exc,
        ) from exc


def _parse_request_plan(value: object, *, expected_leaf: str) -> RequestPlan:
    request = _object(value, "publication request plan")
    _exact_keys(
        request,
        frozenset({"bytes", "leaf", "sha256"}),
        "publication request plan",
    )
    _require(
        request["leaf"] == expected_leaf
        and type(request["bytes"]) is int
        and 0 < request["bytes"] <= 64 * 1024,
        "publication request plan identity differs",
    )
    return RequestPlan(
        leaf=expected_leaf,
        size=request["bytes"],
        sha256=_sha256(request["sha256"], "publication request plan"),
    )


def _parse_asset_plan(
    value: object,
    *,
    domain: str,
    expected_name: str,
    expected_content_type: str,
) -> AssetPlan:
    asset = _object(value, f"{domain} asset plan")
    _exact_keys(
        asset,
        frozenset({"bytes", "content_type", "name", "sha256", "staging_leaf"}),
        f"{domain} asset plan",
    )
    expected_leaf = f"{domain}--{expected_name}"
    _require(
        asset["name"] == expected_name
        and asset["content_type"] == expected_content_type
        and asset["staging_leaf"] == expected_leaf
        and type(asset["bytes"]) is int
        and 0 < asset["bytes"] <= 512 * 1024 * 1024,
        f"{domain} asset plan binding differs for {expected_name}",
    )
    return AssetPlan(
        name=expected_name,
        size=asset["bytes"],
        sha256=_sha256(asset["sha256"], f"{domain} asset {expected_name}"),
        content_type=expected_content_type,
        staging_leaf=expected_leaf,
    )


def _parse_release_plan(value: object, *, domain: str) -> ReleasePlan:
    release = _object(value, f"{domain} release plan")
    _exact_keys(
        release,
        frozenset(
            {
                "assets",
                "body",
                "create_request",
                "domain",
                "make_latest",
                "publish_request",
                "tag",
                "tag_object",
                "title",
            }
        ),
        f"{domain} release plan",
    )
    if domain == "apple":
        expected_names = apple_contract.APPLE_PUBLIC_ASSET_NAMES
        expected_types = apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES
        expected_tag = apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"]
        expected_title = APPLE_TITLE
        expected_body = APPLE_BODY
        expected_latest = True
    else:
        expected_names = platform_contract.PUBLIC_ASSET_NAMES
        expected_types = platform_contract.PUBLIC_ASSET_CONTENT_TYPES
        expected_tag = platform_contract.RELEASE_TAG
        expected_title = PLATFORM_TITLE
        expected_body = PLATFORM_BODY
        expected_latest = False
    assets_value = release["assets"]
    _require(
        release["domain"] == domain
        and release["tag"] == expected_tag
        and release["title"] == expected_title
        and release["body"] == expected_body
        and release["make_latest"] is expected_latest
        and isinstance(assets_value, list)
        and len(assets_value) == len(expected_names),
        f"{domain} release plan policy differs",
    )
    assets = tuple(
        _parse_asset_plan(
            assets_value[index],
            domain=domain,
            expected_name=name,
            expected_content_type=expected_types[name],
        )
        for index, name in enumerate(expected_names)
    )
    return ReleasePlan(
        domain=domain,
        tag=expected_tag,
        tag_object=_sha1(release["tag_object"], f"{domain} tag object"),
        title=expected_title,
        body=expected_body,
        make_latest=expected_latest,
        assets=assets,
        create_request=_parse_request_plan(
            release["create_request"], expected_leaf=f"create-{domain}.json"
        ),
        publish_request=_parse_request_plan(
            release["publish_request"], expected_leaf=f"publish-{domain}.json"
        ),
    )


def parse_plan(value: object) -> PublicationPlan:
    document = _object(value, "stable GitHub publication plan")
    _exact_keys(
        document,
        frozenset(
            {
                "api_version",
                "boundary",
                "github_cli_sha256",
                "kind",
                "releases",
                "repository",
                "results",
                "schema_version",
                "source",
            }
        ),
        "stable GitHub publication plan",
    )
    _require(
        type(document["schema_version"]) is int
        and document["schema_version"] == PLAN_SCHEMA_VERSION
        and document["kind"] == PLAN_KIND
        and document["boundary"] == BOUNDARY
        and document["repository"] == REPOSITORY
        and document["api_version"] == github_release.GITHUB_API_VERSION,
        "stable GitHub publication plan discriminant differs",
    )
    results = _object(document["results"], "publication plan results")
    _exact_keys(
        results,
        frozenset({"commit", "platform_candidate_receipt_sha256", "sha256"}),
        "publication plan results",
    )
    source = _object(document["source"], "publication plan source")
    _exact_keys(
        source,
        frozenset(
            {
                "canonical_source_tree_sha256",
                "source_parent_commit",
                "tag_commit",
                "tag_tree",
            }
        ),
        "publication plan source",
    )
    releases_value = document["releases"]
    _require(
        isinstance(releases_value, list) and len(releases_value) == 2,
        "publication plan release count differs",
    )
    plan = PublicationPlan(
        results_sha256=_sha256(results["sha256"], "pending results"),
        pending_commit=_sha1(results["commit"], "pending results commit"),
        source_parent_commit=_sha1(
            source["source_parent_commit"], "source parent commit"
        ),
        tag_commit=_sha1(source["tag_commit"], "stable tag commit"),
        tag_tree=_sha1(source["tag_tree"], "stable tag tree"),
        canonical_source_tree_sha256=_sha256(
            source["canonical_source_tree_sha256"], "canonical source tree"
        ),
        platform_candidate_receipt_sha256=_sha256(
            results["platform_candidate_receipt_sha256"],
            "platform candidate receipt",
        ),
        github_cli_sha256=_sha256(document["github_cli_sha256"], "GitHub CLI"),
        releases=(
            _parse_release_plan(releases_value[0], domain="apple"),
            _parse_release_plan(releases_value[1], domain="platform"),
        ),
    )
    _require(
        plan.source_parent_commit != plan.tag_commit
        and plan.apple.tag_object != plan.platform.tag_object
        and plan.tag_commit
        not in {plan.apple.tag_object, plan.platform.tag_object},
        "publication plan Git object identities differ",
    )
    _require(
        plan.github_cli_sha256 == github_release.GITHUB_CLI_SHA256,
        "publication plan GitHub CLI digest differs from source policy",
    )
    for release in plan.releases:
        create_bytes = _create_request_bytes(
            tag=release.tag,
            title=release.title,
            body=release.body,
            make_latest=release.make_latest,
            tag_commit=plan.tag_commit,
        )
        publish_bytes = _publish_request_bytes(
            tag=release.tag,
            title=release.title,
            body=release.body,
            make_latest=release.make_latest,
            tag_commit=plan.tag_commit,
        )
        _require(
            release.create_request.size == len(create_bytes)
            and release.create_request.sha256
            == hashlib.sha256(create_bytes).hexdigest()
            and release.publish_request.size == len(publish_bytes)
            and release.publish_request.sha256
            == hashlib.sha256(publish_bytes).hexdigest(),
            f"{release.domain} request plan differs from fixed canonical bytes",
        )
    github_release.validate_mutable_release_policy(plan.policies()[0])
    github_release.validate_mutable_release_policy(plan.policies()[1])
    return plan


def action_sequence(plan: PublicationPlan) -> tuple[MutationAction, ...]:
    actions: list[MutationAction] = [
        MutationAction(0, "create-apple-draft", "create", "apple"),
        MutationAction(1, "create-platform-draft", "create", "platform"),
    ]
    for asset_index, asset in enumerate(plan.apple.assets):
        actions.append(
            MutationAction(
                len(actions),
                f"upload-apple-{asset_index:02d}-{asset.name}",
                "upload",
                "apple",
                asset_index,
            )
        )
    for asset_index, asset in enumerate(plan.platform.assets):
        actions.append(
            MutationAction(
                len(actions),
                f"upload-platform-{asset_index:02d}-{asset.name}",
                "upload",
                "platform",
                asset_index,
            )
        )
    actions.extend(
        (
            MutationAction(len(actions), "publish-apple", "publish", "apple"),
            MutationAction(
                len(actions) + 1,
                "publish-platform",
                "publish",
                "platform",
            ),
        )
    )
    _require(len(actions) == MAX_ACTIONS, "publication action count differs")
    return tuple(actions)


def classify_remote_state(
    plan: PublicationPlan,
    snapshot: RemoteSnapshot,
) -> ClassifiedRemoteState:
    _sha256(snapshot.tag_protection_sha256, "tag protection observation")
    _sha256(snapshot.tag_state_sha256, "tag state observation")
    remote = snapshot.releases
    _require(
        remote.immutable_enabled is True and bool(remote.repository_canonical),
        "GitHub repository or immutable-release boundary differs",
    )
    apple, platform = remote.releases
    apple_count = len(plan.apple.assets)
    platform_count = len(plan.platform.assets)
    if apple is None and platform is None:
        _require(
            remote.latest_tag is None,
            "a non-prerelease latest release exists before the first stable release",
        )
        return ClassifiedRemoteState(0, "both_absent")
    _require(apple is not None, "platform release exists before Apple")
    if platform is None:
        _require(remote.latest_tag is None, "draft Apple release became latest")
        _require(
            apple.draft and not apple.immutable and len(apple.assets) == 0,
            "Apple-only remote state is not the empty first draft",
        )
        return ClassifiedRemoteState(1, "apple_draft")
    _require(
        apple.release_id != platform.release_id,
        "the two releases share one remote ID",
    )
    if apple.draft:
        _require(remote.latest_tag is None, "a draft transaction changed latest")
        _require(platform.draft, "platform was published before Apple")
        _require(
            not apple.immutable and not platform.immutable,
            "draft release claims immutability",
        )
        if len(apple.assets) < apple_count:
            _require(
                len(platform.assets) == 0,
                "platform assets exist before the Apple prefix is complete",
            )
            return ClassifiedRemoteState(
                2 + len(apple.assets), f"apple_prefix_{len(apple.assets)}"
            )
        _require(
            len(apple.assets) == apple_count,
            "Apple draft asset count differs",
        )
        return ClassifiedRemoteState(
            2 + apple_count + len(platform.assets),
            f"platform_prefix_{len(platform.assets)}",
        )
    _require(
        apple.immutable
        and not apple.draft
        and len(apple.assets) == apple_count
        and apple.is_latest
        and remote.latest_tag == plan.apple.tag,
        "published Apple release is not the exact immutable latest release",
    )
    if platform.draft:
        _require(
            not platform.immutable and len(platform.assets) == platform_count,
            "Apple was published before the complete platform draft",
        )
        return ClassifiedRemoteState(MAX_ACTIONS - 1, "apple_published")
    _require(
        platform.immutable
        and not platform.is_latest
        and len(platform.assets) == platform_count
        and remote.latest_tag == plan.apple.tag,
        "final platform release or latest-release policy differs",
    )
    return ClassifiedRemoteState(MAX_ACTIONS, "both_published")


def _account_home() -> pathlib.Path:
    _require(os.name == "posix", "publication state requires POSIX")
    try:
        home_text = pwd.getpwuid(os.geteuid()).pw_dir
    except (KeyError, OSError) as exc:
        raise StableGitHubPublicationError(
            "cannot resolve the publication account home"
        ) from exc
    _require(
        isinstance(home_text, str)
        and os.path.isabs(home_text)
        and os.path.abspath(home_text) == home_text,
        "publication account home is malformed",
    )
    home = pathlib.Path(home_text)
    try:
        resolved = home.resolve(strict=True)
    except OSError as exc:
        raise StableGitHubPublicationError(
            "cannot inspect the publication account home"
        ) from exc
    _require(
        resolved == home,
        "publication account home is not canonical",
    )
    for ancestor in (home, *home.parents):
        try:
            metadata = ancestor.lstat()
        except OSError as exc:
            raise StableGitHubPublicationError(
                "cannot inspect publication account ancestry"
            ) from exc
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid in {0, os.geteuid()}
            and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
            and (ancestor != home or metadata.st_uid == os.geteuid()),
            "publication account ancestry is not trusted",
        )
    return home


def expected_state_root() -> pathlib.Path:
    return (
        _account_home()
        / ".q-periapt"
        / "publication-state"
        / "github-stable-v0.1.3"
    )


def _registered_worktrees() -> tuple[pathlib.Path, ...]:
    try:
        raw = run_git_bytes(
            REPOSITORY_ROOT, ["worktree", "list", "--porcelain", "-z"]
        )
    except GitProvenanceError as exc:
        raise StableGitHubPublicationError(
            "cannot enumerate registered Git worktrees"
        ) from exc
    _require(raw.endswith(b"\0\0"), "registered worktree inventory is malformed")
    roots: list[pathlib.Path] = []
    for record in raw[:-2].split(b"\0\0"):
        fields = record.split(b"\0")
        _require(
            fields and fields[0].startswith(b"worktree "),
            "registered worktree record is malformed",
        )
        try:
            text = fields[0].removeprefix(b"worktree ").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StableGitHubPublicationError(
                "registered worktree path is not UTF-8"
            ) from exc
        _require(
            os.path.isabs(text) and os.path.abspath(text) == text,
            "registered worktree path is malformed",
        )
        roots.append(pathlib.Path(os.path.realpath(text)))
    _require(roots and len(roots) == len(set(roots)), "worktree inventory differs")
    return tuple(roots)


def validate_state_root(state_root: pathlib.Path | None = None) -> pathlib.Path:
    expected = expected_state_root()
    selected = expected if state_root is None else state_root
    _require(
        isinstance(selected, pathlib.Path)
        and selected == expected
        and os.fspath(selected) == os.fspath(expected),
        "publication state root differs from the passwd-derived authority",
    )
    for directory in (
        expected.parent.parent,
        expected.parent,
        expected,
    ):
        try:
            metadata = directory.lstat()
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise StableGitHubPublicationError(
                "fixed publication directories must be created as mode-0700"
            ) from exc
        _require(
            resolved == directory
            and stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "fixed publication directories must be owned mode-0700 directories",
        )
    try:
        root = normalize_safe_root(expected, label="stable GitHub publication state")
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub publication state-root boundary failed",
            preceding_error=exc,
        ) from exc
    for worktree in _registered_worktrees():
        _require(
            root != worktree and not root.is_relative_to(worktree),
            "publication state root is inside a registered worktree",
        )
    return root


def ensure_state_root_for_prepare(
    state_root: pathlib.Path | None = None,
) -> tuple[pathlib.Path, PrivateSafeRootCreatedIdentity | None]:
    """Create only the fixed passwd-home private chain used by ``prepare``."""

    expected = expected_state_root()
    selected = expected if state_root is None else state_root
    _require(
        isinstance(selected, pathlib.Path)
        and selected == expected
        and os.fspath(selected) == os.fspath(expected),
        "publication state root differs from the passwd-derived authority",
    )
    for worktree in _registered_worktrees():
        _require(
            expected != worktree and not expected.is_relative_to(worktree),
            "publication state root is inside a registered worktree",
        )
    for directory, label in (
        (expected.parent.parent, "publication account authority"),
        (expected.parent, "publication state authority"),
    ):
        try:
            ensure_private_safe_root(directory, label=label)
        except PublicationReceiptIOError as exc:
            raise StableGitHubPublicationBoundaryIntegrityError(
                "cannot establish the fixed private publication state",
                preceding_error=exc,
            ) from exc
    try:
        _normalized, created_root_identity = ensure_private_safe_root_with_creation(
            expected,
            label="stable GitHub publication state",
        )
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "cannot establish the fixed private publication state",
            preceding_error=exc,
        ) from exc
    return validate_state_root(expected), created_root_identity


@contextlib.contextmanager
def publication_lock(
    state_root: pathlib.Path | None = None,
    *,
    allow_create: bool,
    created_root_identity: PrivateSafeRootCreatedIdentity | None = None,
) -> Iterator[PrivateFileLockHandle]:
    root = validate_state_root(state_root)
    try:
        with exclusive_private_file_lock(
            root,
            LOCK_LEAF,
            label="stable GitHub publication lock",
            allow_create=allow_create,
            created_root_identity=created_root_identity,
        ) as handle:
            yield handle
    except PublicationLockHeldError as exc:
        raise StableGitHubPublicationLockHeld(str(exc)) from exc
    except PublicationBoundaryIntegrityError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub publication local boundary integrity failed",
            preceding_error=exc,
        ) from exc
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub publication lock boundary failed",
            preceding_error=exc,
        ) from exc


def _create_request_bytes(
    *, tag: str, title: str, body: str,
    make_latest: bool, tag_commit: str
) -> bytes:
    return canonical_json_bytes(
        {
            "body": body,
            "draft": True,
            "generate_release_notes": False,
            "make_latest": "true" if make_latest else "false",
            "name": title,
            "prerelease": False,
            "tag_name": tag,
            "target_commitish": tag_commit,
        }
    )


def _publish_request_bytes(
    *, tag: str, title: str, body: str, make_latest: bool, tag_commit: str
) -> bytes:
    return canonical_json_bytes(
        {
            "body": body,
            "draft": False,
            "make_latest": "true" if make_latest else "false",
            "name": title,
            "prerelease": False,
            "tag_name": tag,
            "target_commitish": tag_commit,
        }
    )


def _request_plan(leaf: str, payload: bytes) -> RequestPlan:
    return RequestPlan(
        leaf=leaf,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _local_tag_object(tag: str, expected_commit: str, expected_tree: str) -> str:
    try:
        tag_type = run_git_text(
            REPOSITORY_ROOT, ["cat-file", "-t", f"refs/tags/{tag}"]
        )
        tag_object = run_git_text(
            REPOSITORY_ROOT, ["rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}"]
        )
        commit = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"],
        )
        tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"refs/tags/{tag}^{{tree}}"],
        )
    except GitProvenanceError as exc:
        raise StableGitHubPublicationError(
            "cannot verify a local stable annotated tag"
        ) from exc
    _require(
        tag_type == "tag"
        and HEX_40.fullmatch(tag_object) is not None
        and tag_object != expected_commit
        and commit == expected_commit
        and tree == expected_tree,
        "local stable annotated tag binding differs",
    )
    return tag_object


class DigestSnapshot(Protocol):
    size: int
    sha256: str


def _asset_plans(
    domain: str,
    names: Sequence[str],
    content_types: Mapping[str, str],
    snapshots: Mapping[str, DigestSnapshot],
) -> tuple[AssetPlan, ...]:
    return tuple(
        AssetPlan(
            name=name,
            size=snapshots[name].size,
            sha256=snapshots[name].sha256,
            content_type=content_types[name],
            staging_leaf=f"{domain}--{name}",
        )
        for name in names
    )


def build_plan_from_pending_results(
    expected_results_sha256: str,
) -> tuple[
    PublicationPlan,
    tuple[FileSnapshot, ...],
    dict[str, Any],
    dict[str, Any],
]:
    """Build a deterministic plan without touching credentials or remote state."""

    try:
        committed = load_current_results(expected_results_sha256)
    except ReleaseReceiptFinalizerError as exc:
        raise StableGitHubPublicationError(str(exc)) from exc
    manifest = committed.manifest
    _require(
        publication_state(manifest) == PUBLICATION_STATE_PENDING,
        "stable GitHub publication requires the installed pending cohort P",
    )
    identity = stable_source_identity(manifest)
    if identity is None:
        _fail("pending results lack stable source identity")
    try:
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            identity.source_parent_commit,
            identity.tag_commit,
        )
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            identity.tag_commit,
            committed.commit,
        )
    except GitProvenanceError as exc:
        raise StableGitHubPublicationError(
            "stable publication requires exact direct S-to-R-to-P results-only commits"
        ) from exc
    publications = _object(manifest["release_publications"], "pending publications")
    apple_pending = _object(
        publications[apple_contract.APPLE_V0_1_3_PUBLICATION_KEY],
        "pending Apple publication",
    )
    platform_pending = _object(
        publications[platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY],
        "pending platform publication",
    )
    platform_observation = _object(
        platform_pending["observation"], "pending platform observation"
    )
    platform_source = _object(
        platform_observation["source"], "pending platform source"
    )
    platform_candidate = _object(
        platform_observation["release_candidate"],
        "pending platform release candidate",
    )
    assembly_receipt_sha256 = _sha256(
        platform_observation["assembly_receipt_sha256"],
        "pending platform assembly receipt",
    )
    apple_snapshots = apple_stable_publication.load_pending_publication_assets(
        apple_pending
    )
    platform_bundle = platform_distribution.find_selected_release_candidate_bundle(
        platform_candidate,
        platform_source,
        expected_receipt_sha256=assembly_receipt_sha256,
    )
    apple_tag_object = _local_tag_object(
        apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"],
        identity.tag_commit,
        identity.tag_tree,
    )
    platform_tag_object = _local_tag_object(
        platform_contract.RELEASE_TAG,
        identity.tag_commit,
        identity.tag_tree,
    )
    _require(
        apple_pending["source"]["tag_object"] == apple_tag_object
        and platform_source["tag_object"] == platform_tag_object,
        "pending receipts differ from the local annotated tag objects",
    )
    apple_by_name = dict(
        zip(
            apple_contract.APPLE_PUBLIC_ASSET_NAMES,
            apple_snapshots,
            strict=True,
        )
    )
    platform_by_name = platform_bundle.asset_by_name()
    create_apple = _create_request_bytes(
        tag=apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"],
        title=APPLE_TITLE,
        body=APPLE_BODY,
        make_latest=True,
        tag_commit=identity.tag_commit,
    )
    create_platform = _create_request_bytes(
        tag=platform_contract.RELEASE_TAG,
        title=PLATFORM_TITLE,
        body=PLATFORM_BODY,
        make_latest=False,
        tag_commit=identity.tag_commit,
    )
    plan = PublicationPlan(
        results_sha256=committed.sha256,
        pending_commit=committed.commit,
        source_parent_commit=identity.source_parent_commit,
        tag_commit=identity.tag_commit,
        tag_tree=identity.tag_tree,
        canonical_source_tree_sha256=identity.canonical_source_tree_sha256,
        platform_candidate_receipt_sha256=assembly_receipt_sha256,
        github_cli_sha256=github_release.select_github_cli().sha256,
        releases=(
            ReleasePlan(
                domain="apple",
                tag=apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"],
                tag_object=apple_tag_object,
                title=APPLE_TITLE,
                body=APPLE_BODY,
                make_latest=True,
                assets=_asset_plans(
                    "apple",
                    apple_contract.APPLE_PUBLIC_ASSET_NAMES,
                    apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES,
                    apple_by_name,
                ),
                create_request=_request_plan("create-apple.json", create_apple),
                publish_request=_request_plan(
                    "publish-apple.json",
                    _publish_request_bytes(
                        tag=apple_contract.APPLE_V0_1_3_IDENTITY["release_tag"],
                        title=APPLE_TITLE,
                        body=APPLE_BODY,
                        make_latest=True,
                        tag_commit=identity.tag_commit,
                    ),
                ),
            ),
            ReleasePlan(
                domain="platform",
                tag=platform_contract.RELEASE_TAG,
                tag_object=platform_tag_object,
                title=PLATFORM_TITLE,
                body=PLATFORM_BODY,
                make_latest=False,
                assets=_asset_plans(
                    "platform",
                    platform_contract.PUBLIC_ASSET_NAMES,
                    platform_contract.PUBLIC_ASSET_CONTENT_TYPES,
                    platform_by_name,
                ),
                create_request=_request_plan(
                    "create-platform.json", create_platform
                ),
                publish_request=_request_plan(
                    "publish-platform.json",
                    _publish_request_bytes(
                        tag=platform_contract.RELEASE_TAG,
                        title=PLATFORM_TITLE,
                        body=PLATFORM_BODY,
                        make_latest=False,
                        tag_commit=identity.tag_commit,
                    ),
                ),
            ),
        ),
    )
    parse_plan(plan.document())
    return plan, apple_snapshots, platform_candidate, platform_source


def _private_file_metadata(metadata: os.stat_result) -> None:
    _require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE
        and metadata.st_nlink == 1,
        "publication state file metadata differs",
    )


def _ensure_child_directory(root: pathlib.Path, name: str) -> None:
    child = root / name
    try:
        metadata = child.lstat()
    except FileNotFoundError:
        with create_private_direct_child_handle(
            safe_root=root,
            direct_child_name=name,
            label=f"stable GitHub publication {name}",
        ):
            return
    except OSError as exc:
        raise StableGitHubPublicationError(
            "cannot inspect a publication state directory"
        ) from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
        and not child.is_symlink(),
        "publication state child directory metadata differs",
    )


_ROOT_FIXED_LEAVES = frozenset(
    {
        LOCK_LEAF,
        PREPARATION_INTENT_LEAF,
        PLAN_LEAF,
        STAGING_DIRECTORY,
        REQUEST_DIRECTORY,
        JOURNAL_DIRECTORY,
    }
)


def _recover_state_root_residues(root_descriptor: int) -> None:
    try:
        recover_private_staging_residues_at(
            root_descriptor,
            _ROOT_FIXED_LEAVES,
            label="stable GitHub state root",
            recoverable_final_leaves=frozenset(
                {PREPARATION_INTENT_LEAF, PLAN_LEAF}
            ),
        )
    except PublicationBoundaryIntegrityError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub state-root residue recovery lost integrity",
            preceding_error=exc,
        ) from exc
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationError(str(exc)) from exc


def _verify_state_root_inventory_at(
    root_descriptor: int,
    expected: frozenset[str],
) -> None:
    try:
        verify_exact_directory_inventory_at(
            root_descriptor,
            expected,
            label="stable GitHub state root",
        )
    except PublicationBoundaryIntegrityError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub state-root inventory lost integrity",
            preceding_error=exc,
        ) from exc
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub state-root inventory differs",
            preceding_error=exc,
        ) from exc


def _request_payloads(plan: PublicationPlan) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for release in plan.releases:
        payloads[release.create_request.leaf] = _create_request_bytes(
            tag=release.tag,
            title=release.title,
            body=release.body,
            make_latest=release.make_latest,
            tag_commit=plan.tag_commit,
        )
        payloads[release.publish_request.leaf] = _publish_request_bytes(
            tag=release.tag,
            title=release.title,
            body=release.body,
            make_latest=release.make_latest,
            tag_commit=plan.tag_commit,
        )
    return payloads


def _stage_bytes(
    directory: PrivateDirectoryHandle,
    leaf: str,
    payload: bytes,
    *,
    expected_sha256: str,
    allow_existing: bool,
    label: str,
) -> None:
    try:
        os.stat(leaf, dir_fd=directory.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        digest = write_private_bytes_noreplace_at(
            directory.descriptor,
            leaf,
            payload,
            label=label,
            maximum=max(len(payload), 1),
        )
        _require(digest == expected_sha256, f"{label} staged digest differs")
        return
    except OSError as exc:
        raise StableGitHubPublicationError(f"cannot inspect {label}") from exc
    _require(allow_existing, f"existing {label} lacks same-plan recovery authority")
    try:
        existing = consume_regular_snapshot_at(
            directory.descriptor,
            leaf,
            display_path=pathlib.Path(leaf),
            maximum=max(len(payload), 1),
            label=label,
            validate_metadata=_private_file_metadata,
        )
    except (EvidenceIOError, OSError, StableGitHubPublicationError) as exc:
        raise StableGitHubPublicationError(f"cannot verify existing {label}") from exc
    _require(
        existing.size == len(payload)
        and existing.sha256 == expected_sha256
        and hashlib.sha256(payload).hexdigest() == expected_sha256,
        f"existing {label} bytes differ",
    )


def _read_plan_leaf(root: pathlib.Path, leaf: str) -> PublicationPlan:
    snapshot = read_fixed_json_snapshot(
        root / leaf,
        safe_root=root,
        expected_leaf=leaf,
        label=f"stable GitHub {leaf}",
        parent_depth=0,
        maximum=MAX_PLAN_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    plan_value = snapshot.value
    _require(
        snapshot.file.data == canonical_json_bytes(plan_value),
        f"stable GitHub {leaf} is not canonical JSON",
    )
    if leaf == PREPARATION_INTENT_LEAF:
        intent = _object(plan_value, "stable GitHub preparation intent")
        _exact_keys(
            intent,
            frozenset({"kind", "plan", "plan_sha256", "schema_version"}),
            "stable GitHub preparation intent",
        )
        _require(
            type(intent["schema_version"]) is int
            and intent["kind"] == "qperiapt.stable_github_preparation_intent"
            and intent["schema_version"] == 1,
            "stable GitHub preparation intent discriminant differs",
        )
        plan = parse_plan(intent["plan"])
        _require(
            intent["plan_sha256"] == plan.sha256(),
            "stable GitHub preparation intent digest differs",
        )
        return plan
    return parse_plan(plan_value)


def validate_plan_against_pending_manifest(
    plan: PublicationPlan,
    manifest: dict[str, object],
) -> None:
    """Rebind every publication authority field to the installed pending P.

    This deliberately consumes only facts retained in ``results.json``.  A
    completed prepare therefore never depends on disposable candidate-cache or
    Apple distribution paths remaining available.
    """

    _require(
        publication_state(manifest) == PUBLICATION_STATE_PENDING,
        "installed results are not the coordinated pending publication",
    )
    identity = stable_source_identity(manifest)
    _require(identity is not None, "installed results lack stable source identity")
    try:
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            identity.source_parent_commit,
            identity.tag_commit,
        )
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            identity.tag_commit,
            plan.pending_commit,
        )
    except GitProvenanceError as exc:
        raise StableGitHubPublicationError(
            "stable publication requires exact direct S-to-R-to-P results-only commits"
        ) from exc
    _require(
        (
            plan.source_parent_commit,
            plan.tag_commit,
            plan.tag_tree,
            plan.canonical_source_tree_sha256,
        )
        == (
            identity.source_parent_commit,
            identity.tag_commit,
            identity.tag_tree,
            identity.canonical_source_tree_sha256,
        ),
        "publication plan source identity differs from pending results",
    )
    publications = _object(manifest["release_publications"], "pending publications")
    apple_pending = _object(
        publications[apple_contract.APPLE_V0_1_3_PUBLICATION_KEY],
        "pending Apple publication",
    )
    apple_source = _object(apple_pending["source"], "pending Apple source")
    apple_distribution = _object(
        apple_pending["distribution"], "pending Apple distribution"
    )
    apple_digests = apple_contract.apple_public_asset_sha256s(apple_distribution)
    _require(
        plan.apple.tag_object == apple_source["tag_object"]
        and apple_source["source_parent_commit"] == plan.source_parent_commit
        and apple_source["tag_commit"] == plan.tag_commit
        and apple_source["tag_tree"] == plan.tag_tree
        and apple_source["canonical_source_tree_sha256"]
        == plan.canonical_source_tree_sha256,
        "publication plan Apple source differs from pending results",
    )
    _require(
        tuple(asset.name for asset in plan.apple.assets)
        == apple_contract.APPLE_PUBLIC_ASSET_NAMES
        and all(
            asset.sha256 == apple_digests[asset.name]
            and asset.content_type
            == apple_contract.APPLE_PUBLIC_ASSET_CONTENT_TYPES[asset.name]
            for asset in plan.apple.assets
        ),
        "publication plan Apple assets differ from pending results",
    )
    apple_zip = next(
        asset
        for asset in plan.apple.assets
        if asset.name == apple_contract.APPLE_XCFRAMEWORK_ARTIFACT_PATH
    )
    _require(
        type(apple_distribution["artifact_size"]) is int
        and apple_zip.size == apple_distribution["artifact_size"],
        "publication plan Apple artifact size differs from pending results",
    )

    platform_pending = _object(
        publications[platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY],
        "pending platform publication",
    )
    platform_observation = _object(
        platform_pending["observation"], "pending platform observation"
    )
    platform_source = _object(
        platform_observation["source"], "pending platform source"
    )
    platform_candidate = _object(
        platform_observation["release_candidate"],
        "pending platform release candidate",
    )
    candidate_assets_value = platform_candidate["assets"]
    _require(
        isinstance(candidate_assets_value, list),
        "pending platform candidate assets are malformed",
    )
    candidate_assets = {
        _object(value, "pending platform candidate asset")["name"]: _object(
            value, "pending platform candidate asset"
        )
        for value in candidate_assets_value
    }
    _require(
        plan.platform_candidate_receipt_sha256
        == platform_observation["assembly_receipt_sha256"]
        and plan.platform.tag_object == platform_source["tag_object"]
        and platform_source["source_parent_commit"] == plan.source_parent_commit
        and platform_source["tag_commit"] == plan.tag_commit
        and platform_source["tag_tree"] == plan.tag_tree
        and platform_source["canonical_source_tree_sha256"]
        == plan.canonical_source_tree_sha256,
        "publication plan platform provenance differs from pending results",
    )
    _require(
        tuple(asset.name for asset in plan.platform.assets)
        == platform_contract.PUBLIC_ASSET_NAMES
        and frozenset(candidate_assets) == frozenset(platform_contract.PUBLIC_ASSET_NAMES),
        "publication plan platform asset inventory differs from pending results",
    )
    for asset in plan.platform.assets:
        expected = candidate_assets[asset.name]
        _require(
            expected.get("name") == asset.name
            and expected.get("bytes") == asset.size
            and expected.get("sha256") == asset.sha256
            and expected.get("content_type") == asset.content_type
            and asset.content_type
            == platform_contract.PUBLIC_ASSET_CONTENT_TYPES[asset.name],
            f"publication plan platform asset differs for {asset.name}",
        )

    _require(
        _local_tag_object(plan.apple.tag, plan.tag_commit, plan.tag_tree)
        == plan.apple.tag_object
        and _local_tag_object(plan.platform.tag, plan.tag_commit, plan.tag_tree)
        == plan.platform.tag_object,
        "local annotated stable tag objects differ from pending results",
    )


def _validate_plan_against_current_pending(
    plan: PublicationPlan,
    *,
    expected_results_sha256: str | None = None,
) -> None:
    if expected_results_sha256 is not None:
        _require(
            plan.results_sha256 == expected_results_sha256,
            "publication plan binds different pending results",
        )
    try:
        committed = load_current_results(plan.results_sha256)
    except ReleaseReceiptFinalizerError as exc:
        raise StableGitHubPublicationError(str(exc)) from exc
    _require(
        committed.sha256 == plan.results_sha256
        and committed.commit == plan.pending_commit
        and publication_state(committed.manifest) == PUBLICATION_STATE_PENDING,
        "installed pending results differ from the publication plan",
    )
    validate_plan_against_pending_manifest(plan, committed.manifest)
    tool = github_release.select_github_cli()
    _require(
        tool.sha256 == plan.github_cli_sha256,
        "pinned GitHub CLI differs from the publication plan",
    )


def _validate_staged_asset_prefix(
    staging: PrivateDirectoryHandle,
    plan: PublicationPlan,
) -> bool:
    assets = {
        asset.staging_leaf: (release.domain, asset)
        for release in plan.releases
        for asset in release.assets
    }
    try:
        entries = frozenset(os.listdir(staging.descriptor))
    except OSError as exc:
        raise StableGitHubPublicationError(
            "cannot inspect stable GitHub staged assets"
        ) from exc
    _require(
        len(entries) <= len(assets) and entries <= frozenset(assets),
        "stable GitHub staged asset inventory is not a planned prefix",
    )
    for leaf in entries:
        domain, asset = assets[leaf]
        with open_pinned_private_file_at(
            staging.descriptor,
            leaf,
            expected_size=asset.size,
            expected_sha256=asset.sha256,
            maximum=512 * 1024 * 1024,
            label=f"staged {domain} asset {asset.name}",
        ) as descriptor:
            os.lseek(descriptor, asset.size, os.SEEK_SET)
    return len(entries) == len(assets)


def _verify_planned_files(
    root: pathlib.Path,
    plan: PublicationPlan,
) -> None:
    with contextlib.ExitStack() as resources:
        staging = resources.enter_context(
            open_private_direct_child_handle(
                safe_root=root,
                direct_child_name=STAGING_DIRECTORY,
                label="stable GitHub staging directory",
            )
        )
        requests = resources.enter_context(
            open_private_direct_child_handle(
                safe_root=root,
                direct_child_name=REQUEST_DIRECTORY,
                label="stable GitHub request directory",
            )
        )
        expected_assets = frozenset(
            asset.staging_leaf
            for release in plan.releases
            for asset in release.assets
        )
        expected_requests = frozenset(_request_payloads(plan))
        verify_exact_directory_inventory_at(
            staging.descriptor,
            expected_assets,
            label="stable GitHub staged assets",
        )
        verify_exact_directory_inventory_at(
            requests.descriptor,
            expected_requests,
            label="stable GitHub request bodies",
        )
        for release in plan.releases:
            for asset in release.assets:
                with open_pinned_private_file_at(
                    staging.descriptor,
                    asset.staging_leaf,
                    expected_size=asset.size,
                    expected_sha256=asset.sha256,
                    maximum=512 * 1024 * 1024,
                    label=f"staged {release.domain} asset {asset.name}",
                ) as descriptor:
                    os.lseek(descriptor, asset.size, os.SEEK_SET)
        payloads = _request_payloads(plan)
        request_plans = {
            request.leaf: request
            for release in plan.releases
            for request in (release.create_request, release.publish_request)
        }
        for leaf, payload in payloads.items():
            request = request_plans[leaf]
            _require(
                len(payload) == request.size
                and hashlib.sha256(payload).hexdigest() == request.sha256,
                f"planned request bytes differ for {leaf}",
            )
            with open_pinned_private_file_at(
                requests.descriptor,
                leaf,
                expected_size=request.size,
                expected_sha256=request.sha256,
                maximum=64 * 1024,
                label=f"staged request {leaf}",
            ) as descriptor:
                os.lseek(descriptor, request.size, os.SEEK_SET)


def verify_local_plan(
    root: pathlib.Path,
    plan: PublicationPlan,
) -> None:
    try:
        root_descriptor = os.open(
            root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise StableGitHubPublicationError(
            "cannot open stable GitHub state root"
        ) from exc
    try:
        _verify_state_root_inventory_at(root_descriptor, _ROOT_FIXED_LEAVES)
    finally:
        try:
            os.close(root_descriptor)
        except OSError as exc:
            raise StableGitHubPublicationBoundaryIntegrityError(
                "cannot close stable GitHub state-root verifier",
                preceding_error=exc,
            ) from exc
    try:
        _validate_plan_against_current_pending(plan)
    except _LOCAL_GITHUB_INTEGRITY_ERRORS as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "local GitHub tool identity changed from the publication plan",
            preceding_error=exc,
        ) from exc
    parsed = _read_plan_leaf(root, PLAN_LEAF)
    intent = _read_plan_leaf(root, PREPARATION_INTENT_LEAF)
    _require(
        parsed == plan and intent == plan,
        "publication plan and preparation intent differ",
    )
    _verify_planned_files(root, plan)


def prepare_plan(
    expected_results_sha256: str,
    *,
    state_root: pathlib.Path | None = None,
) -> PublicationPlan:
    root, created_root_identity = ensure_state_root_for_prepare(state_root)
    with publication_lock(
        root,
        allow_create=created_root_identity is not None,
        created_root_identity=created_root_identity,
    ) as lock:
        root_descriptor = lock.root_descriptor
        _recover_state_root_residues(root_descriptor)
        try:
            os.stat(PLAN_LEAF, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _verify_state_root_inventory_at(root_descriptor, _ROOT_FIXED_LEAVES)
            existing = _read_plan_leaf(root, PLAN_LEAF)
            _require(
                existing.results_sha256 == expected_results_sha256,
                "existing publication plan binds different pending results",
            )
            verify_local_plan(root, existing)
            verify_private_file_lock(lock, label="stable GitHub publication lock")
            return existing
        current_root_entries = frozenset(os.listdir(root_descriptor))
        preplan_entries = frozenset(
            {
                LOCK_LEAF,
                PREPARATION_INTENT_LEAF,
                STAGING_DIRECTORY,
                REQUEST_DIRECTORY,
                JOURNAL_DIRECTORY,
            }
        )
        _require(current_root_entries <= preplan_entries, (
            "unrecognized publication state-root entries exist"
        ))
        has_preparation_intent = PREPARATION_INTENT_LEAF in current_root_entries
        apple_snapshots: tuple[FileSnapshot, ...] | None = None
        platform_candidate: dict[str, Any] | None = None
        platform_source: dict[str, Any] | None = None
        if has_preparation_intent:
            _require(
                current_root_entries == preplan_entries,
                "durable preparation intent lacks its complete local authority",
            )
            plan = _read_plan_leaf(root, PREPARATION_INTENT_LEAF)
            try:
                _validate_plan_against_current_pending(
                    plan,
                    expected_results_sha256=expected_results_sha256,
                )
            except _LOCAL_GITHUB_INTEGRITY_ERRORS as exc:
                raise StableGitHubPublicationBoundaryIntegrityError(
                    "local GitHub tool identity changed during preparation recovery",
                    preceding_error=exc,
                ) from exc
        else:
            _require(
                current_root_entries
                <= frozenset(
                    {
                        LOCK_LEAF,
                        STAGING_DIRECTORY,
                        REQUEST_DIRECTORY,
                        JOURNAL_DIRECTORY,
                    }
                ),
                "pre-intent publication state is malformed",
            )
            plan, apple_snapshots, platform_candidate, platform_source = (
                build_plan_from_pending_results(expected_results_sha256)
            )
            for directory_name in (
                STAGING_DIRECTORY,
                REQUEST_DIRECTORY,
                JOURNAL_DIRECTORY,
            ):
                _ensure_child_directory(root, directory_name)
        with contextlib.ExitStack() as resources:
            staging = resources.enter_context(
                open_private_direct_child_handle(
                    safe_root=root,
                    direct_child_name=STAGING_DIRECTORY,
                    label="stable GitHub staging directory",
                )
            )
            requests = resources.enter_context(
                open_private_direct_child_handle(
                    safe_root=root,
                    direct_child_name=REQUEST_DIRECTORY,
                    label="stable GitHub request directory",
                )
            )
            journal = resources.enter_context(
                open_private_direct_child_handle(
                    safe_root=root,
                    direct_child_name=JOURNAL_DIRECTORY,
                    label="stable GitHub journal directory",
                )
            )
            if not has_preparation_intent:
                verify_exact_directory_inventory_at(
                    staging.descriptor,
                    frozenset(),
                    label="new stable GitHub staging directory",
                )
                verify_exact_directory_inventory_at(
                    requests.descriptor,
                    frozenset(),
                    label="new stable GitHub request directory",
                )
                verify_exact_directory_inventory_at(
                    journal.descriptor,
                    frozenset(),
                    label="new stable GitHub journal directory",
                )
                intent_value = {
                    "kind": "qperiapt.stable_github_preparation_intent",
                    "plan": plan.document(),
                    "plan_sha256": plan.sha256(),
                    "schema_version": 1,
                }
                write_private_json_noreplace_at(
                    root_descriptor,
                    PREPARATION_INTENT_LEAF,
                    intent_value,
                    label="stable GitHub preparation intent",
                    maximum=MAX_PLAN_BYTES,
                )
            else:
                recover_private_staging_residues_at(
                    staging.descriptor,
                    frozenset(
                        asset.staging_leaf
                        for release in plan.releases
                        for asset in release.assets
                    ),
                    label="stable GitHub asset staging",
                )
                recover_private_staging_residues_at(
                    requests.descriptor,
                    frozenset(_request_payloads(plan)),
                    label="stable GitHub request staging",
                )
            assets_complete = _validate_staged_asset_prefix(staging, plan)
            if not assets_complete:
                if apple_snapshots is None:
                    (
                        rebuilt_plan,
                        apple_snapshots,
                        platform_candidate,
                        platform_source,
                    ) = build_plan_from_pending_results(expected_results_sha256)
                    _require(
                        rebuilt_plan == plan,
                        "recovered preparation sources bind a different plan",
                    )
                _require(
                    apple_snapshots is not None
                    and platform_candidate is not None
                    and platform_source is not None,
                    "missing staged assets lack their plan-selected source authority",
                )
                apple_by_name = dict(
                    zip(
                        apple_contract.APPLE_PUBLIC_ASSET_NAMES,
                        apple_snapshots,
                        strict=True,
                    )
                )
                for asset in plan.apple.assets:
                    snapshot = apple_by_name[asset.name]
                    _stage_bytes(
                        staging,
                        asset.staging_leaf,
                        snapshot.data,
                        expected_sha256=asset.sha256,
                        allow_existing=True,
                        label=f"Apple publication asset {asset.name}",
                    )
                platform_distribution.find_selected_release_candidate_bundle(
                    platform_candidate,
                    platform_source,
                    staging_directory_fd=staging.descriptor,
                    staging_leaves={
                        asset.name: asset.staging_leaf
                        for asset in plan.platform.assets
                    },
                    expected_receipt_sha256=(
                        plan.platform_candidate_receipt_sha256
                    ),
                    allow_existing_staging=True,
                )
                _require(
                    _validate_staged_asset_prefix(staging, plan),
                    "stable GitHub staged assets remain incomplete",
                )
            payloads = _request_payloads(plan)
            request_plans = {
                request.leaf: request
                for release in plan.releases
                for request in (release.create_request, release.publish_request)
            }
            for leaf, payload in payloads.items():
                request = request_plans[leaf]
                _stage_bytes(
                    requests,
                    leaf,
                    payload,
                    expected_sha256=request.sha256,
                    allow_existing=True,
                    label=f"GitHub mutation request {leaf}",
                )
            verify_exact_directory_inventory_at(
                journal.descriptor,
                frozenset(),
                label="stable GitHub prepublication journal",
            )
        verify_private_file_lock(lock, label="stable GitHub publication lock")
        write_private_json_noreplace_at(
            root_descriptor,
            PLAN_LEAF,
            plan.document(),
            label="stable GitHub publication plan",
            maximum=MAX_PLAN_BYTES,
        )
        _verify_state_root_inventory_at(root_descriptor, _ROOT_FIXED_LEAVES)
        verify_local_plan(root, plan)
        verify_private_file_lock(lock, label="stable GitHub publication lock")
        return plan


@dataclasses.dataclass(frozen=True, slots=True)
class JournalCursor:
    applied_count: int
    last_projection: dict[str, Any] | None
    trailing_intent: dict[str, Any] | None
    trailing_reconciliation: dict[str, Any] | None


@dataclasses.dataclass(frozen=True, slots=True)
class PublicationStatus:
    plan_sha256: str
    state_index: int
    state_name: str
    applied_actions: int
    unresolved_intent: bool
    reconciliation_eligible: bool
    manual_review_required: bool
    complete: bool


def _remote_projection(snapshot: RemoteSnapshot) -> dict[str, Any]:
    try:
        release_value = parse_strict_json_bytes(
            snapshot.releases.canonical,
            label="stable GitHub canonical remote observation",
        )
    except EvidenceIOError as exc:
        raise StableGitHubPublicationError(
            "canonical remote observation is malformed"
        ) from exc
    release = _object(release_value, "stable GitHub remote observation")
    projection = {
        "release_observation": release,
        "tag_protection_sha256": _sha256(
            snapshot.tag_protection_sha256, "remote tag protection"
        ),
        "tag_state_sha256": _sha256(snapshot.tag_state_sha256, "remote tag state"),
    }
    _validate_remote_projection(projection)
    return projection


def _validate_remote_projection(value: object) -> dict[str, Any]:
    projection = _object(value, "journal remote projection")
    _exact_keys(
        projection,
        frozenset(
            {
                "release_observation",
                "tag_protection_sha256",
                "tag_state_sha256",
            }
        ),
        "journal remote projection",
    )
    _sha256(projection["tag_protection_sha256"], "journal tag protection")
    _sha256(projection["tag_state_sha256"], "journal tag state")
    release = _object(
        projection["release_observation"], "journal release observation"
    )
    _exact_keys(
        release,
        frozenset(
            {
                "immutable_enabled",
                "immutable_enforced_by_owner",
                "latest_tag",
                "releases",
                "repository_sha256",
            }
        ),
        "journal release observation",
    )
    releases = release["releases"]
    _require(
        release["immutable_enabled"] is True
        and type(release["immutable_enforced_by_owner"]) is bool
        and (release["latest_tag"] is None or isinstance(release["latest_tag"], str))
        and isinstance(releases, list)
        and len(releases) == 2,
        "journal release observation fields differ",
    )
    _sha256(release["repository_sha256"], "journal repository observation")
    return projection


def _snapshot_from_projection(
    plan: PublicationPlan,
    value: object,
) -> RemoteSnapshot:
    """Deep-parse a journal projection back into the typed remote domain."""

    projection = _validate_remote_projection(value)
    release_document = _object(
        projection["release_observation"], "journal release observation"
    )
    release_values = release_document["releases"]
    _require(isinstance(release_values, list), "journal release pair is malformed")
    parsed_releases: list[github_release.MutableReleaseView | None] = []
    global_asset_ids: set[int] = set()
    global_node_ids: set[str] = set()
    for release_index, raw_release in enumerate(release_values):
        if raw_release is None:
            parsed_releases.append(None)
            continue
        release_plan = plan.releases[release_index]
        release = _object(raw_release, "journal release view")
        _exact_keys(
            release,
            frozenset(
                {
                    "assets",
                    "body",
                    "draft",
                    "immutable",
                    "is_latest",
                    "prerelease",
                    "published_at",
                    "release_id",
                    "tag",
                    "target_commitish",
                    "title",
                }
            ),
            "journal release view",
        )
        assets_value = release["assets"]
        _require(
            release["tag"] == release_plan.tag
            and release["title"] == release_plan.title
            and release["body"] == release_plan.body
            and release["target_commitish"] in {"main", plan.tag_commit}
            and type(release["draft"]) is bool
            and type(release["immutable"]) is bool
            and type(release["is_latest"]) is bool
            and release["prerelease"] is False
            and type(release["release_id"]) is int
            and 0 < release["release_id"] < (1 << 63)
            and isinstance(assets_value, list)
            and len(assets_value) <= len(release_plan.assets),
            "journal release identity or flags differ from plan",
        )
        published_time = None
        if release["draft"]:
            _require(
                release["immutable"] is False
                and release["is_latest"] is False
                and release["published_at"] is None,
                "journal draft release flags differ",
            )
        else:
            _require(
                release["immutable"] is True
                and isinstance(release["published_at"], str),
                "journal public release is not immutable",
            )
            published_time = github_release.parse_utc_timestamp(
                release["published_at"], "journal release published_at"
            )
        parsed_assets: list[github_release.MutableReleaseAsset] = []
        for asset_index, raw_asset in enumerate(assets_value):
            expected = release_plan.assets[asset_index]
            asset = _object(raw_asset, "journal release asset")
            _exact_keys(
                asset,
                frozenset(
                    {
                        "asset_id",
                        "content_type",
                        "created_at",
                        "name",
                        "node_id",
                        "sha256",
                        "size",
                        "state",
                        "updated_at",
                    }
                ),
                "journal release asset",
            )
            asset_id = asset["asset_id"]
            node_id = asset["node_id"]
            _require(
                type(asset_id) is int
                and 0 < asset_id < (1 << 63)
                and isinstance(node_id, str)
                and re.fullmatch(r"[0-9A-Za-z_-]{1,256}", node_id) is not None
                and asset_id not in global_asset_ids
                and node_id not in global_node_ids
                and asset["name"] == expected.name
                and type(asset["size"]) is int
                and asset["size"] == expected.size
                and asset["sha256"] == expected.sha256
                and asset["content_type"] == expected.content_type
                and asset["state"] == "uploaded"
                and isinstance(asset["created_at"], str)
                and isinstance(asset["updated_at"], str),
                "journal release asset identity or bytes differ from plan",
            )
            created_time = github_release.parse_utc_timestamp(
                asset["created_at"], "journal asset created_at"
            )
            updated_time = github_release.parse_utc_timestamp(
                asset["updated_at"], "journal asset updated_at"
            )
            _require(
                created_time <= updated_time
                and (
                    release["draft"] is True
                    or (
                        published_time is not None
                        and updated_time <= published_time
                    )
                ),
                "journal release asset timestamps are out of order",
            )
            global_asset_ids.add(asset_id)
            global_node_ids.add(node_id)
            parsed_assets.append(
                github_release.MutableReleaseAsset(
                    asset_id=asset_id,
                    node_id=node_id,
                    name=expected.name,
                    size=expected.size,
                    sha256=expected.sha256,
                    content_type=expected.content_type,
                    state="uploaded",
                    created_at=asset["created_at"],
                    updated_at=asset["updated_at"],
                )
            )
        parsed_releases.append(
            github_release.MutableReleaseView(
                release_id=release["release_id"],
                tag=release_plan.tag,
                draft=release["draft"],
                immutable=release["immutable"],
                prerelease=False,
                is_latest=release["is_latest"],
                published_at=release["published_at"],
                assets=tuple(parsed_assets),
                canonical=canonical_json_bytes(release),
            )
        )
    _require(
        len(parsed_releases) == 2,
        "journal release pair count differs",
    )
    observation = github_release.MutableReleaseTransactionObservation(
        repository_canonical=(
            b"sha256:" + str(release_document["repository_sha256"]).encode("ascii")
        ),
        immutable_enabled=True,
        immutable_enforced_by_owner=release_document[
            "immutable_enforced_by_owner"
        ],
        latest_tag=release_document["latest_tag"],
        releases=(parsed_releases[0], parsed_releases[1]),
        canonical=canonical_json_bytes(release_document),
    )
    snapshot = RemoteSnapshot(
        releases=observation,
        tag_protection_sha256=projection["tag_protection_sha256"],
        tag_state_sha256=projection["tag_state_sha256"],
    )
    classify_remote_state(plan, snapshot)
    return snapshot


def _projection_sha256(projection: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def _release_pair(projection: Mapping[str, object]) -> list[object]:
    release = _object(
        projection["release_observation"], "transition release observation"
    )
    releases = release["releases"]
    _require(
        isinstance(releases, list) and len(releases) == 2,
        "transition release pair differs",
    )
    return releases


def _transition_release_common(
    before: Mapping[str, object],
    after: Mapping[str, object],
    *,
    excluded: frozenset[str],
    label: str,
) -> None:
    _require(
        before.keys() == after.keys()
        and all(
            before[key] == after[key]
            for key in before
            if key not in excluded
        ),
        f"{label} changed fields outside the admitted mutation",
    )


def validate_exact_remote_transition(
    plan: PublicationPlan,
    action: MutationAction,
    before_value: object,
    after_snapshot: RemoteSnapshot,
) -> None:
    """Prove the action changed only the one intended remote object."""

    before = _validate_remote_projection(before_value)
    after = _remote_projection(after_snapshot)
    _require(
        before["tag_protection_sha256"] == after["tag_protection_sha256"]
        and before["tag_state_sha256"] == after["tag_state_sha256"],
        "stable tag authority changed across a release mutation",
    )
    before_observation = _object(
        before["release_observation"], "pre-mutation release observation"
    )
    after_observation = _object(
        after["release_observation"], "post-mutation release observation"
    )
    _require(
        before_observation["repository_sha256"]
        == after_observation["repository_sha256"]
        and before_observation["immutable_enabled"]
        == after_observation["immutable_enabled"]
        and before_observation["immutable_enforced_by_owner"]
        == after_observation["immutable_enforced_by_owner"],
        "repository or immutable-release authority changed across mutation",
    )
    before_releases = _release_pair(before)
    after_releases = _release_pair(after)
    target = 0 if action.domain == "apple" else 1
    other = 1 - target
    _require(
        before_releases[other] == after_releases[other],
        "the non-target release changed across mutation",
    )
    before_target = before_releases[target]
    after_target = after_releases[target]
    if action.kind == "create":
        _require(
            before_target is None and isinstance(after_target, dict),
            "draft creation did not add exactly the intended release",
        )
        created = _object(after_target, "created release")
        _require(
            created.get("draft") is True
            and created.get("immutable") is False
            and created.get("published_at") is None
            and created.get("is_latest") is False
            and created.get("assets") == [],
            "created release is not the exact empty draft",
        )
        _require(
            before_observation["latest_tag"] == after_observation["latest_tag"],
            "draft creation changed the latest release",
        )
        return
    _require(
        isinstance(before_target, dict) and isinstance(after_target, dict),
        "mutation target release is absent",
    )
    before_release = _object(before_target, "pre-mutation target release")
    after_release = _object(after_target, "post-mutation target release")
    if action.kind == "upload":
        _transition_release_common(
            before_release,
            after_release,
            excluded=frozenset({"assets"}),
            label="asset upload",
        )
        before_assets = before_release["assets"]
        after_assets = after_release["assets"]
        _require(
            isinstance(before_assets, list)
            and isinstance(after_assets, list)
            and after_assets[:-1] == before_assets
            and len(after_assets) == len(before_assets) + 1,
            "asset upload did not append exactly one planned identity",
        )
        _require(
            before_observation["latest_tag"] == after_observation["latest_tag"],
            "asset upload changed the latest release",
        )
        return
    _require(action.kind == "publish", "publication action kind is unknown")
    # ``target_commitish`` legitimately normalizes on publish: GitHub echoes the
    # created commitish (the tag commit SHA) while the release is a draft and
    # rewrites it to the default branch name once the tag ref is materialized.
    # parse_mutable_release_view independently bounds it to {"main", tag_commit},
    # so excluding it from the byte-equality here does not weaken the proof.
    _transition_release_common(
        before_release,
        after_release,
        excluded=frozenset(
            {"draft", "immutable", "is_latest", "published_at", "target_commitish"}
        ),
        label="release publication",
    )
    expected_latest = action.domain == "apple"
    _require(
        before_release.get("draft") is True
        and before_release.get("immutable") is False
        and before_release.get("published_at") is None
        and after_release.get("draft") is False
        and after_release.get("immutable") is True
        and after_release.get("is_latest") is expected_latest
        and isinstance(after_release.get("published_at"), str),
        "release publication flags differ",
    )
    if action.domain == "apple":
        _require(
            before_observation["latest_tag"] is None
            and after_observation["latest_tag"] == plan.apple.tag,
            "Apple publication did not establish the sole latest release",
        )
    else:
        _require(
            before_observation["latest_tag"] == plan.apple.tag
            and after_observation["latest_tag"] == plan.apple.tag,
            "platform publication changed the latest release",
        )


def _observe_remote_composite_once(
    plan: PublicationPlan,
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: github_release.GitHubCommandRunner = capture_stdout,
) -> RemoteSnapshot:
    protection_before = github_release.sample_stable_tag_protection_once(
        source_environment=source_environment,
        runner=runner,
    )
    tag_before = github_release.sample_stable_tag_state_once(
        expected_commit=plan.tag_commit,
        expected_tree=plan.tag_tree,
        expected_tag_objects=(plan.apple.tag_object, plan.platform.tag_object),
        source_environment=source_environment,
        runner=runner,
    )
    releases = github_release.sample_mutable_release_transaction_once(
        plan.policies(),
        source_environment=source_environment,
        runner=runner,
    )
    tag_after = github_release.sample_stable_tag_state_once(
        expected_commit=plan.tag_commit,
        expected_tree=plan.tag_tree,
        expected_tag_objects=(plan.apple.tag_object, plan.platform.tag_object),
        source_environment=source_environment,
        runner=runner,
    )
    protection_after = github_release.sample_stable_tag_protection_once(
        source_environment=source_environment,
        runner=runner,
    )
    _require(
        tag_before == tag_after
        and tag_before.state == "exact"
        and protection_before == protection_after,
        "stable tag state or protection changed across release observation",
    )
    return RemoteSnapshot(
        releases=releases,
        tag_protection_sha256=protection_before.observation_sha256,
        tag_state_sha256=tag_before.observation_sha256,
    )


def observe_remote_transaction(
    plan: PublicationPlan,
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: github_release.GitHubCommandRunner = capture_stdout,
) -> RemoteSnapshot:
    """Double-sample the complete protection/tag/release composite."""

    before = _observe_remote_composite_once(
        plan,
        source_environment=source_environment,
        runner=runner,
    )
    after = _observe_remote_composite_once(
        plan,
        source_environment=source_environment,
        runner=runner,
    )
    _require(
        before.canonical() == after.canonical()
        and before.releases == after.releases,
        "complete stable GitHub remote state changed between samples",
    )
    return before


def _journal_intent_leaf(index: int) -> str:
    return f"{index:06d}-intent.json"


def _journal_outcome_leaf(index: int) -> str:
    return f"{index:06d}-outcome.json"


def _journal_reconciliation_leaf(index: int) -> str:
    return f"{index:06d}-reconciliation.json"


def _journal_final_leaves() -> frozenset[str]:
    return frozenset(
        leaf
        for index in range(MAX_ACTIONS)
        for leaf in (
            _journal_intent_leaf(index),
            _journal_reconciliation_leaf(index),
            _journal_outcome_leaf(index),
        )
    )


def _read_canonical_json_at(
    directory: PrivateDirectoryHandle,
    leaf: str,
) -> tuple[dict[str, Any], str]:
    try:
        chunks: list[bytes] = []
        snapshot = consume_regular_snapshot_at(
            directory.descriptor,
            leaf,
            display_path=pathlib.Path(leaf),
            maximum=MAX_JOURNAL_BYTES,
            label="stable GitHub journal record",
            consume=chunks.append,
            validate_metadata=_private_file_metadata,
        )
        data = b"".join(chunks)
        _require(
            len(data) == snapshot.size,
            "stable GitHub journal byte count differs",
        )
        value = parse_strict_json_bytes(
            data,
            label="stable GitHub journal record",
        )
    except EvidenceIOError as exc:
        raise StableGitHubPublicationError(
            "stable GitHub journal record is invalid"
        ) from exc
    record = _object(value, "stable GitHub journal record")
    _require(
        data == canonical_json_bytes(record),
        "stable GitHub journal record is not canonical JSON",
    )
    return record, snapshot.sha256


def _parse_intent_record(
    value: object,
    *,
    action: MutationAction,
    plan: PublicationPlan,
) -> dict[str, Any]:
    record = _object(value, "stable GitHub mutation intent")
    _exact_keys(
        record,
        frozenset(
            {
                "action_id",
                "kind",
                "plan_sha256",
                "post_index",
                "pre_index",
                "pre_remote",
                "pre_remote_sha256",
                "record",
                "schema_version",
                "sequence",
            }
        ),
        "stable GitHub mutation intent",
    )
    pre_remote = _validate_remote_projection(record["pre_remote"])
    pre_snapshot = _snapshot_from_projection(plan, pre_remote)
    pre_state = classify_remote_state(plan, pre_snapshot)
    _require(
        type(record["schema_version"]) is int
        and type(record["sequence"]) is int
        and type(record["pre_index"]) is int
        and type(record["post_index"]) is int
        and record["schema_version"] == JOURNAL_SCHEMA_VERSION
        and record["kind"] == JOURNAL_KIND
        and record["record"] == "intent"
        and record["sequence"] == action.index
        and record["action_id"] == action.action_id
        and record["plan_sha256"] == plan.sha256()
        and record["pre_index"] == action.index
        and record["post_index"] == action.index + 1
        and record["pre_remote_sha256"] == _projection_sha256(pre_remote),
        "stable GitHub mutation intent binding differs",
    )
    _require(
        pre_state.index == action.index,
        "stable GitHub mutation intent remote predecessor is not its true index",
    )
    return record


def _validate_execution_projection(
    value: object,
    *,
    reconciliation_authority: bool,
) -> dict[str, Any]:
    execution = _object(value, "stable GitHub mutation execution")
    _exact_keys(
        execution,
        frozenset({"error_kind", "returncode", "status"}),
        "stable GitHub mutation execution",
    )
    status = execution["status"]
    failure_status = (
        "cli_failure"
        if reconciliation_authority
        else "cli_failure_reconciled"
    )
    _require(
        status in {"runner_success", failure_status},
        "stable GitHub mutation execution status differs",
    )
    if status == failure_status:
        _require(
            (
                execution["error_kind"] is None
                or (
                    isinstance(execution["error_kind"], str)
                    and execution["error_kind"]
                    in BOUNDED_PROCESS_ERROR_KINDS
                )
            )
            and (
                execution["returncode"] is None
                or (
                    type(execution["returncode"]) is int
                    and -255 <= execution["returncode"] <= 255
                    and execution["returncode"] != 0
                )
            )
            and (
                execution["error_kind"] is not None
                or execution["returncode"] is not None
            ),
            "reconciled CLI failure classification is malformed",
        )
    else:
        _require(
            execution["error_kind"] is None
            and execution["returncode"] is None,
            "successful mutation execution carries failure metadata",
        )
    return execution


def _parse_reconciliation_record(
    value: object,
    *,
    action: MutationAction,
    plan: PublicationPlan,
    intent_sha256: str,
) -> dict[str, Any]:
    record = _object(value, "stable GitHub reconciliation authority")
    _exact_keys(
        record,
        frozenset(
            {
                "action_id",
                "execution",
                "intent_sha256",
                "kind",
                "plan_sha256",
                "record",
                "schema_version",
                "sequence",
            }
        ),
        "stable GitHub reconciliation authority",
    )
    execution = _validate_execution_projection(
        record["execution"],
        reconciliation_authority=True,
    )
    _require(
        type(record["schema_version"]) is int
        and type(record["sequence"]) is int
        and record["schema_version"] == JOURNAL_SCHEMA_VERSION
        and record["kind"] == JOURNAL_KIND
        and record["record"] == "reconciliation"
        and record["sequence"] == action.index
        and record["action_id"] == action.action_id
        and record["plan_sha256"] == plan.sha256()
        and record["intent_sha256"] == intent_sha256,
        "stable GitHub reconciliation authority binding differs",
    )
    record["execution"] = execution
    return record


def _outcome_execution_from_authority(value: object) -> dict[str, Any]:
    authority = _validate_execution_projection(
        value,
        reconciliation_authority=True,
    )
    return {
        "error_kind": authority["error_kind"],
        "returncode": authority["returncode"],
        "status": (
            "runner_success"
            if authority["status"] == "runner_success"
            else "cli_failure_reconciled"
        ),
    }


def _parse_outcome_record(
    value: object,
    *,
    action: MutationAction,
    plan: PublicationPlan,
    intent: Mapping[str, object],
    intent_sha256: str,
    reconciliation: Mapping[str, object],
) -> dict[str, Any]:
    record = _object(value, "stable GitHub mutation outcome")
    _exact_keys(
        record,
        frozenset(
            {
                "action_id",
                "intent_sha256",
                "kind",
                "execution",
                "observed_index",
                "observed_remote",
                "observed_remote_sha256",
                "plan_sha256",
                "record",
                "result",
                "schema_version",
                "sequence",
            }
        ),
        "stable GitHub mutation outcome",
    )
    observed = _validate_remote_projection(record["observed_remote"])
    execution = _validate_execution_projection(
        record["execution"],
        reconciliation_authority=False,
    )
    _require(
        _outcome_execution_from_authority(
            reconciliation["execution"]
        )
        == execution,
        "mutation outcome differs from its reconciliation authority",
    )
    observed_snapshot = _snapshot_from_projection(plan, observed)
    observed_state = classify_remote_state(plan, observed_snapshot)
    _require(
        type(record["schema_version"]) is int
        and type(record["sequence"]) is int
        and type(record["observed_index"]) is int
        and record["schema_version"] == JOURNAL_SCHEMA_VERSION
        and record["kind"] == JOURNAL_KIND
        and record["record"] == "outcome"
        and record["sequence"] == action.index
        and record["action_id"] == action.action_id
        and record["plan_sha256"] == plan.sha256()
        and record["intent_sha256"] == intent_sha256
        and record["result"] == "applied"
        and record["observed_index"] == observed_state.index
        and record["observed_remote_sha256"] == _projection_sha256(observed),
        "stable GitHub mutation outcome binding differs",
    )
    _require(
        record["observed_index"] == action.index + 1,
        "applied mutation outcome has the wrong successor index",
    )
    validate_exact_remote_transition(
        plan,
        action,
        intent["pre_remote"],
        observed_snapshot,
    )
    return record


def load_journal(
    directory: PrivateDirectoryHandle,
    plan: PublicationPlan,
    *,
    recover_residues: bool,
) -> JournalCursor:
    finals = _journal_final_leaves()
    if recover_residues:
        try:
            recover_private_staging_residues_at(
                directory.descriptor,
                finals,
                label="stable GitHub journal",
            )
        except PublicationBoundaryIntegrityError as exc:
            raise StableGitHubPublicationBoundaryIntegrityError(
                "stable GitHub journal residue recovery lost integrity",
                preceding_error=exc,
            ) from exc
        except PublicationReceiptIOError as exc:
            raise StableGitHubPublicationError(str(exc)) from exc
    entries = frozenset(os.listdir(directory.descriptor))
    _require(
        len(entries) <= 3 * MAX_ACTIONS
        and entries <= finals
        and all(JOURNAL_LEAF.fullmatch(entry) is not None for entry in entries),
        "stable GitHub journal inventory is malformed",
    )
    actions = action_sequence(plan)
    last_projection: dict[str, Any] | None = None
    for action in actions:
        intent_leaf = _journal_intent_leaf(action.index)
        reconciliation_leaf = _journal_reconciliation_leaf(action.index)
        outcome_leaf = _journal_outcome_leaf(action.index)
        if intent_leaf not in entries:
            _require(
                reconciliation_leaf not in entries
                and outcome_leaf not in entries
                and not any(
                    _journal_intent_leaf(later.index) in entries
                    or _journal_reconciliation_leaf(later.index) in entries
                    or _journal_outcome_leaf(later.index) in entries
                    for later in actions[action.index + 1 :]
                ),
                "stable GitHub journal has a gap",
            )
            return JournalCursor(action.index, last_projection, None, None)
        intent, intent_sha256 = _read_canonical_json_at(directory, intent_leaf)
        intent = _parse_intent_record(
            intent,
            action=action,
            plan=plan,
        )
        if last_projection is not None:
            _require(
                intent["pre_remote"] == last_projection,
                "stable GitHub journal successor does not chain to prior outcome",
            )
        reconciliation: dict[str, Any] | None = None
        if reconciliation_leaf in entries:
            reconciliation_value, _reconciliation_sha256 = (
                _read_canonical_json_at(directory, reconciliation_leaf)
            )
            reconciliation = _parse_reconciliation_record(
                reconciliation_value,
                action=action,
                plan=plan,
                intent_sha256=intent_sha256,
            )
        if outcome_leaf not in entries:
            _require(
                not any(
                    _journal_intent_leaf(later.index) in entries
                    or _journal_reconciliation_leaf(later.index) in entries
                    or _journal_outcome_leaf(later.index) in entries
                    for later in actions[action.index + 1 :]
                ),
                "stable GitHub journal continues after a trailing intent",
            )
            return JournalCursor(
                action.index,
                last_projection,
                intent,
                reconciliation,
            )
        if reconciliation is None:
            _fail(
                "stable GitHub mutation outcome lacks reconciliation authority"
            )
        outcome, _outcome_sha256 = _read_canonical_json_at(directory, outcome_leaf)
        outcome = _parse_outcome_record(
            outcome,
            action=action,
            plan=plan,
            intent=intent,
            intent_sha256=intent_sha256,
            reconciliation=reconciliation,
        )
        last_projection = outcome["observed_remote"]
    return JournalCursor(MAX_ACTIONS, last_projection, None, None)


def _write_intent(
    directory: PrivateDirectoryHandle,
    plan: PublicationPlan,
    action: MutationAction,
    before: RemoteSnapshot,
) -> dict[str, Any]:
    projection = _remote_projection(before)
    record = {
        "action_id": action.action_id,
        "kind": JOURNAL_KIND,
        "plan_sha256": plan.sha256(),
        "post_index": action.index + 1,
        "pre_index": action.index,
        "pre_remote": projection,
        "pre_remote_sha256": _projection_sha256(projection),
        "record": "intent",
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "sequence": action.index,
    }
    write_private_json_noreplace_at(
        directory.descriptor,
        _journal_intent_leaf(action.index),
        record,
        label="stable GitHub mutation intent",
        maximum=MAX_JOURNAL_BYTES,
    )
    return record


def _execution_projection(
    cli_failure: github_release.GitHubCliExecutionError | None,
    *,
    reconciliation_authority: bool,
) -> dict[str, object]:
    return {
        "error_kind": None if cli_failure is None else cli_failure.error_kind,
        "returncode": None if cli_failure is None else cli_failure.returncode,
        "status": (
            "runner_success"
            if cli_failure is None
            else (
                "cli_failure"
                if reconciliation_authority
                else "cli_failure_reconciled"
            )
        ),
    }


def _write_reconciliation_authority(
    directory: PrivateDirectoryHandle,
    plan: PublicationPlan,
    action: MutationAction,
    intent: Mapping[str, object],
    *,
    cli_failure: github_release.GitHubCliExecutionError | None,
) -> dict[str, Any]:
    record = {
        "action_id": action.action_id,
        "execution": _execution_projection(
            cli_failure,
            reconciliation_authority=True,
        ),
        "intent_sha256": hashlib.sha256(
            canonical_json_bytes(intent)
        ).hexdigest(),
        "kind": JOURNAL_KIND,
        "plan_sha256": plan.sha256(),
        "record": "reconciliation",
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "sequence": action.index,
    }
    write_private_json_noreplace_at(
        directory.descriptor,
        _journal_reconciliation_leaf(action.index),
        record,
        label="stable GitHub reconciliation authority",
        maximum=MAX_JOURNAL_BYTES,
    )
    return record


def _write_outcome(
    directory: PrivateDirectoryHandle,
    plan: PublicationPlan,
    action: MutationAction,
    intent: Mapping[str, object],
    observed: RemoteSnapshot,
    *,
    cli_failure: github_release.GitHubCliExecutionError | None = None,
    execution: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    _require(
        cli_failure is None or execution is None,
        "mutation outcome has two execution authorities",
    )
    projection = _remote_projection(observed)
    state = classify_remote_state(plan, observed)
    intent_sha256 = hashlib.sha256(canonical_json_bytes(intent)).hexdigest()
    execution_projection = (
        _execution_projection(
            cli_failure,
            reconciliation_authority=False,
        )
        if execution is None
        else _outcome_execution_from_authority(execution)
    )
    record = {
        "action_id": action.action_id,
        "execution": execution_projection,
        "intent_sha256": intent_sha256,
        "kind": JOURNAL_KIND,
        "observed_index": state.index,
        "observed_remote": projection,
        "observed_remote_sha256": _projection_sha256(projection),
        "plan_sha256": plan.sha256(),
        "record": "outcome",
        "result": "applied",
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "sequence": action.index,
    }
    write_private_json_noreplace_at(
        directory.descriptor,
        _journal_outcome_leaf(action.index),
        record,
        label="stable GitHub mutation outcome",
        maximum=MAX_JOURNAL_BYTES,
    )
    return record


def execute_production_mutation(
    root: PrivateDirectoryHandle,
    plan: PublicationPlan,
    action: MutationAction,
    before: RemoteSnapshot,
    *,
    source_environment: Mapping[str, str] | None = None,
    runner: github_release.GitHubInputRunner = capture_stdout,
) -> None:
    """Execute exactly one planned REST mutation from a pinned staged fd."""

    tool = github_release.select_github_cli()
    _require(
        tool.sha256 == plan.github_cli_sha256,
        "pinned GitHub CLI differs from the publication plan",
    )
    environment = github_release.github_cli_environment(
        os.environ if source_environment is None else source_environment
    )
    release = plan.apple if action.domain == "apple" else plan.platform
    remote_release = before.releases.releases[
        0 if action.domain == "apple" else 1
    ]
    if action.kind == "upload":
        _require(
            action.asset_index is not None
            and 0 <= action.asset_index < len(release.assets)
            and remote_release is not None
            and remote_release.draft,
            "asset upload predecessor differs",
        )
        asset = release.assets[action.asset_index]
        with open_private_directory_at(
            parent=root,
            direct_child_name=STAGING_DIRECTORY,
            label="stable GitHub staging directory",
        ) as staging:
            with open_pinned_private_file_at(
                staging.descriptor,
                asset.staging_leaf,
                expected_size=asset.size,
                expected_sha256=asset.sha256,
                maximum=512 * 1024 * 1024,
                label=f"GitHub upload body for {asset.name}",
            ) as input_fd:
                github_release.execute_github_api_asset_upload(
                    tool,
                    release_id=remote_release.release_id,
                    asset_name=asset.name,
                    content_type=asset.content_type,
                    input_fd=input_fd,
                    input_size=asset.size,
                    input_sha256=asset.sha256,
                    timeout_seconds=ASSET_UPLOAD_TIMEOUT_SECONDS,
                    maximum_bytes=MAX_MUTATION_OUTPUT_BYTES,
                    environment=environment,
                    label=f"GitHub upload for {action.domain} asset",
                    runner=runner,
                )
        return
    _require(action.asset_index is None, "non-upload action carries an asset index")
    request = (
        release.create_request
        if action.kind == "create"
        else release.publish_request
    )
    _require(
        action.kind in {"create", "publish"},
        "GitHub JSON mutation kind is unknown",
    )
    if action.kind == "create":
        _require(remote_release is None, "draft release already exists")
        method = "POST"
        endpoint = f"/repos/{REPOSITORY}/releases"
    else:
        _require(
            remote_release is not None and remote_release.draft,
            "publish predecessor is not a draft release",
        )
        method = "PATCH"
        endpoint = f"/repos/{REPOSITORY}/releases/{remote_release.release_id}"
    with open_private_directory_at(
        parent=root,
        direct_child_name=REQUEST_DIRECTORY,
        label="stable GitHub request directory",
    ) as requests:
        with open_pinned_private_file_at(
            requests.descriptor,
            request.leaf,
            expected_size=request.size,
            expected_sha256=request.sha256,
            maximum=64 * 1024,
            label=f"GitHub {action.kind} request body",
        ) as input_fd:
            github_release.execute_github_api_json_mutation(
                tool,
                method=method,
                endpoint=endpoint,
                input_fd=input_fd,
                input_size=request.size,
                input_sha256=request.sha256,
                timeout_seconds=JSON_MUTATION_TIMEOUT_SECONDS,
                maximum_bytes=MAX_MUTATION_OUTPUT_BYTES,
                environment=environment,
                label=f"GitHub {action.domain} {action.kind}",
                runner=runner,
            )


def _ensure_cursor_matches_remote(
    plan: PublicationPlan,
    cursor: JournalCursor,
    remote: RemoteSnapshot,
) -> ClassifiedRemoteState:
    state = classify_remote_state(plan, remote)
    current_projection = _remote_projection(remote)
    _require(cursor.trailing_intent is None, "mutation intent is unresolved")
    if cursor.applied_count == 0:
        _require(
            state.index == 0 and cursor.last_projection is None,
            "remote release state lacks same-plan journal provenance",
        )
    else:
        _require(
            state.index == cursor.applied_count
            and cursor.last_projection == current_projection,
            "remote release state differs from the last journaled outcome",
        )
    return state


def _resolve_trailing_intent(
    directory: PrivateDirectoryHandle,
    root: pathlib.Path,
    lock: PrivateFileLockHandle,
    plan: PublicationPlan,
    cursor: JournalCursor,
    remote: RemoteSnapshot,
) -> JournalCursor:
    intent = cursor.trailing_intent
    _require(intent is not None, "no trailing mutation intent exists")
    reconciliation = cursor.trailing_reconciliation
    if reconciliation is None:
        raise StableGitHubPublicationOutcomeUnknown(
            "the mutation intent lacks durable reconciliation authority and requires manual review"
        )
    action = action_sequence(plan)[cursor.applied_count]
    try:
        current_projection = _remote_projection(remote)
        current_state = classify_remote_state(plan, remote)
    except StableGitHubPublicationError as exc:
        raise StableGitHubPublicationOutcomeUnknown(
            "the unresolved mutation cannot be classified from remote state"
        ) from exc
    _verify_mutation_local(root, plan, lock, directory)
    resampled_cursor = load_journal(directory, plan, recover_residues=False)
    _require(
        resampled_cursor.trailing_intent == intent
        and resampled_cursor.trailing_reconciliation == reconciliation
        and resampled_cursor.applied_count == cursor.applied_count,
        "trailing mutation intent changed during remote reconciliation",
    )
    if current_projection == intent["pre_remote"]:
        raise StableGitHubPublicationOutcomeUnknown(
            "an attempted mutation still has its predecessor state; its intent remains unresolved"
        )
    if current_state.index == action.index + 1:
        try:
            validate_exact_remote_transition(
                plan,
                action,
                intent["pre_remote"],
                remote,
            )
        except StableGitHubPublicationError as exc:
            raise StableGitHubPublicationOutcomeUnknown(
                "the remote successor does not prove the intended exact transition"
            ) from exc
        _verify_mutation_local(root, plan, lock, directory)
        final_cursor = load_journal(directory, plan, recover_residues=False)
        _require(
            final_cursor.trailing_intent == intent
            and final_cursor.trailing_reconciliation == reconciliation
            and final_cursor.applied_count == cursor.applied_count,
            "trailing mutation intent changed before durable recovery outcome",
        )
        _write_outcome(
            directory,
            plan,
            action,
            intent,
            remote,
            execution=reconciliation["execution"],
        )
        return load_journal(directory, plan, recover_residues=False)
    raise StableGitHubPublicationOutcomeUnknown(
        "the attempted mutation produced neither its predecessor nor exact successor"
    )


def _load_prepared_plan(root: pathlib.Path) -> PublicationPlan:
    try:
        return _read_plan_leaf(root, PLAN_LEAF)
    except PublicationBoundaryIntegrityError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub plan read lost integrity",
            preceding_error=exc,
        ) from exc
    except PublicationReceiptIOError as exc:
        raise StableGitHubPublicationError(str(exc)) from exc


def _open_journal(
    root: PrivateDirectoryHandle,
) -> contextlib.AbstractContextManager[PrivateDirectoryHandle]:
    return open_private_directory_at(
        parent=root,
        direct_child_name=JOURNAL_DIRECTORY,
        label="stable GitHub journal directory",
    )


def _verify_mutation_local(
    root: pathlib.Path,
    plan: PublicationPlan,
    lock: PrivateFileLockHandle,
    journal: PrivateDirectoryHandle,
    *,
    preceding_error: BaseException | None = None,
) -> None:
    """Revalidate every local authority immediately around a mutation."""

    try:
        verify_private_file_lock(lock, label="stable GitHub publication lock")
        _verify_state_root_inventory_at(lock.root_descriptor, _ROOT_FIXED_LEAVES)
        verify_private_directory_handle_identity(
            journal, label="stable GitHub journal directory"
        )
        verify_local_plan(root, plan)
        verify_private_file_lock(lock, label="stable GitHub publication lock")
        _verify_state_root_inventory_at(lock.root_descriptor, _ROOT_FIXED_LEAVES)
        verify_private_directory_handle_identity(
            journal, label="stable GitHub journal directory"
        )
    except StableGitHubPublicationBoundaryIntegrityError as exc:
        if preceding_error is None:
            raise
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub local mutation boundary lost integrity",
            preceding_error=exc,
            prior_execution_error=preceding_error,
        ) from exc
    except (PublicationBoundaryIntegrityError, PublicationReceiptIOError) as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub local mutation boundary lost integrity",
            preceding_error=exc,
            prior_execution_error=preceding_error,
        ) from exc
    except StableGitHubPublicationError as exc:
        raise StableGitHubPublicationBoundaryIntegrityError(
            "stable GitHub local plan authority changed",
            preceding_error=exc,
            prior_execution_error=preceding_error,
        ) from exc


def _authorize_later_reconciliation(
    root: pathlib.Path,
    lock: PrivateFileLockHandle,
    journal: PrivateDirectoryHandle,
    plan: PublicationPlan,
    action: MutationAction,
    intent: Mapping[str, object],
    *,
    cli_failure: github_release.GitHubCliExecutionError | None,
) -> None:
    """Durably opt a clean local attempt into exact-successor recovery."""

    _verify_mutation_local(
        root,
        plan,
        lock,
        journal,
        preceding_error=cli_failure,
    )
    before = load_journal(journal, plan, recover_residues=False)
    _require(
        before.applied_count == action.index
        and before.trailing_intent == intent
        and before.trailing_reconciliation is None,
        "mutation intent changed before reconciliation authorization",
    )
    expected = _write_reconciliation_authority(
        journal,
        plan,
        action,
        intent,
        cli_failure=cli_failure,
    )
    _verify_mutation_local(
        root,
        plan,
        lock,
        journal,
        preceding_error=cli_failure,
    )
    after = load_journal(journal, plan, recover_residues=False)
    _require(
        after.applied_count == action.index
        and after.trailing_intent == intent
        and after.trailing_reconciliation == expected,
        "durable reconciliation authority changed after commit",
    )


def publish_plan(
    *,
    execute_real_github_mutation: bool,
    expected_plan_sha256: str,
    expected_results_sha256: str,
    draft_barrier_ack: str,
    publication_order_ack: str,
    state_root: pathlib.Path | None = None,
    observer: RemoteObserver | None = None,
    mutator: RemoteMutator | None = None,
    source_environment: Mapping[str, str] | None = None,
    read_runner: github_release.GitHubCommandRunner = capture_stdout,
    mutation_runner: github_release.GitHubInputRunner = capture_stdout,
) -> PublicationStatus:
    _require(
        execute_real_github_mutation is True
        and draft_barrier_ack == ACK_DRAFT_BARRIER
        and publication_order_ack == ACK_PUBLICATION_ORDER,
        "explicit execution and both stable publication acknowledgements are required",
    )
    _sha256(expected_plan_sha256, "expected publication plan")
    _sha256(expected_results_sha256, "expected pending results")
    root = validate_state_root(state_root)
    selected_observer: RemoteObserver = observer or (
        lambda plan: observe_remote_transaction(
            plan,
            source_environment=source_environment,
            runner=read_runner,
        )
    )
    with publication_lock(root, allow_create=False) as lock:
        root_handle = PrivateDirectoryHandle(
            path=root,
            descriptor=lock.root_descriptor,
            parent_descriptor=-1,
            name=root.name,
            device=lock.root_device,
            inode=lock.root_inode,
            mode=0o700,
        )
        selected_mutator: RemoteMutator = mutator or (
            lambda plan, action, before: execute_production_mutation(
                root_handle,
                plan,
                action,
                before,
                source_environment=source_environment,
                runner=mutation_runner,
            )
        )
        _recover_state_root_residues(lock.root_descriptor)
        _verify_state_root_inventory_at(lock.root_descriptor, _ROOT_FIXED_LEAVES)
        plan = _load_prepared_plan(root)
        _require(
            plan.sha256() == expected_plan_sha256
            and plan.results_sha256 == expected_results_sha256,
            "explicit publication plan or pending-results pin differs",
        )
        verify_local_plan(root, plan)
        with _open_journal(root_handle) as journal:
            cursor = load_journal(journal, plan, recover_residues=True)
            remote = _observe_with_local_integrity_priority(
                selected_observer, plan
            )
            if cursor.trailing_intent is not None:
                cursor = _resolve_trailing_intent(
                    journal,
                    root,
                    lock,
                    plan,
                    cursor,
                    remote,
                )
                _verify_mutation_local(root, plan, lock, journal)
                remote = _observe_with_local_integrity_priority(
                    selected_observer, plan
                )
            state = _ensure_cursor_matches_remote(plan, cursor, remote)
            actions = action_sequence(plan)
            while cursor.applied_count < MAX_ACTIONS:
                action = actions[cursor.applied_count]
                _require(
                    state.index == action.index,
                    "journal and action predecessor indices differ",
                )
                _verify_mutation_local(root, plan, lock, journal)
                predecessor = _observe_with_local_integrity_priority(
                    selected_observer, plan
                )
                _ensure_cursor_matches_remote(plan, cursor, predecessor)
                _verify_mutation_local(root, plan, lock, journal)
                intent = _write_intent(journal, plan, action, predecessor)
                _verify_mutation_local(root, plan, lock, journal)
                intent_cursor = load_journal(
                    journal, plan, recover_residues=False
                )
                _require(
                    intent_cursor.applied_count == action.index
                    and intent_cursor.trailing_intent == intent
                    and intent_cursor.trailing_reconciliation is None,
                    "durable mutation intent changed before execution",
                )
                cli_failure: github_release.GitHubCliExecutionError | None = None
                try:
                    selected_mutator(plan, action, predecessor)
                except github_release.GitHubCliExecutionError as exc:
                    cli_failure = exc
                except _LOCAL_GITHUB_INTEGRITY_ERRORS as exc:
                    raise StableGitHubPublicationBoundaryIntegrityError(
                        "local GitHub mutation boundary integrity failed",
                        preceding_error=exc,
                    ) from exc
                _verify_mutation_local(
                    root,
                    plan,
                    lock,
                    journal,
                    preceding_error=cli_failure,
                )
                try:
                    successor = _observe_with_local_integrity_priority(
                        selected_observer, plan
                    )
                except StableGitHubPublicationBoundaryIntegrityError as exc:
                    raise StableGitHubPublicationBoundaryIntegrityError(
                        "local GitHub successor-observation boundary failed",
                        preceding_error=exc,
                        prior_execution_error=cli_failure,
                    ) from exc
                except github_release.GitHubCliExecutionError as exc:
                    _authorize_later_reconciliation(
                        root,
                        lock,
                        journal,
                        plan,
                        action,
                        intent,
                        cli_failure=cli_failure,
                    )
                    raise StableGitHubPublicationOutcomeUnknown(
                        "mutation outcome cannot be observed and remains unresolved"
                    ) from exc
                except (
                    StableGitHubPublicationError,
                    github_release.GitHubReleaseObservationError,
                ) as exc:
                    # The mutation may have taken effect while its immediate
                    # observation was rejected (e.g. a still-propagating remote,
                    # or a draft-shaped field). Record reconciliation authority so
                    # a later, settled observation can prove the exact successor
                    # instead of wedging the transaction in permanent manual review.
                    _authorize_later_reconciliation(
                        root,
                        lock,
                        journal,
                        plan,
                        action,
                        intent,
                        cli_failure=cli_failure,
                    )
                    raise StableGitHubPublicationOutcomeUnknown(
                        "mutation observation is policy-invalid and remains unresolved"
                    ) from exc
                _verify_mutation_local(
                    root,
                    plan,
                    lock,
                    journal,
                    preceding_error=cli_failure,
                )
                post_observation_cursor = load_journal(
                    journal, plan, recover_residues=False
                )
                _require(
                    post_observation_cursor.applied_count == action.index
                    and post_observation_cursor.trailing_intent == intent
                    and post_observation_cursor.trailing_reconciliation is None,
                    "mutation intent changed before outcome reconciliation",
                )
                try:
                    successor_state = classify_remote_state(plan, successor)
                    successor_projection = _remote_projection(successor)
                except StableGitHubPublicationError as exc:
                    _authorize_later_reconciliation(
                        root,
                        lock,
                        journal,
                        plan,
                        action,
                        intent,
                        cli_failure=cli_failure,
                    )
                    raise StableGitHubPublicationOutcomeUnknown(
                        "mutation produced an invalid or unclassifiable remote state"
                    ) from exc
                if successor_projection == intent["pre_remote"]:
                    _authorize_later_reconciliation(
                        root,
                        lock,
                        journal,
                        plan,
                        action,
                        intent,
                        cli_failure=cli_failure,
                    )
                    raise StableGitHubPublicationOutcomeUnknown(
                        "mutation retained its predecessor; its intent remains unresolved"
                    ) from cli_failure
                try:
                    _require(
                        successor_state.index == action.index + 1,
                        "mutation did not reach its exact successor index",
                    )
                    validate_exact_remote_transition(
                        plan,
                        action,
                        intent["pre_remote"],
                        successor,
                    )
                except StableGitHubPublicationError as exc:
                    _authorize_later_reconciliation(
                        root,
                        lock,
                        journal,
                        plan,
                        action,
                        intent,
                        cli_failure=cli_failure,
                    )
                    raise StableGitHubPublicationOutcomeUnknown(
                        "mutation did not produce the exact intended transition"
                    ) from exc
                _authorize_later_reconciliation(
                    root,
                    lock,
                    journal,
                    plan,
                    action,
                    intent,
                    cli_failure=cli_failure,
                )
                final_intent_cursor = load_journal(
                    journal, plan, recover_residues=False
                )
                _require(
                    final_intent_cursor.applied_count == action.index
                    and final_intent_cursor.trailing_intent == intent
                    and final_intent_cursor.trailing_reconciliation is not None,
                    "mutation reconciliation authority changed before durable outcome",
                )
                _write_outcome(
                    journal,
                    plan,
                    action,
                    intent,
                    successor,
                    execution=(
                        final_intent_cursor.trailing_reconciliation[
                            "execution"
                        ]
                    ),
                )
                _verify_mutation_local(
                    root,
                    plan,
                    lock,
                    journal,
                    preceding_error=cli_failure,
                )
                cursor = load_journal(journal, plan, recover_residues=False)
                remote = successor
                state = _ensure_cursor_matches_remote(plan, cursor, remote)
            _require(state.index == MAX_ACTIONS, "publication did not complete")
            return PublicationStatus(
                plan_sha256=plan.sha256(),
                state_index=state.index,
                state_name=state.name,
                applied_actions=cursor.applied_count,
                unresolved_intent=False,
                reconciliation_eligible=False,
                manual_review_required=False,
                complete=True,
            )


def status_plan(
    *,
    state_root: pathlib.Path | None = None,
    observer: RemoteObserver | None = None,
    source_environment: Mapping[str, str] | None = None,
    read_runner: github_release.GitHubCommandRunner = capture_stdout,
) -> PublicationStatus:
    root = validate_state_root(state_root)
    selected_observer: RemoteObserver = observer or (
        lambda plan: observe_remote_transaction(
            plan,
            source_environment=source_environment,
            runner=read_runner,
        )
    )
    with publication_lock(root, allow_create=False) as lock:
        root_handle = PrivateDirectoryHandle(
            path=root,
            descriptor=lock.root_descriptor,
            parent_descriptor=-1,
            name=root.name,
            device=lock.root_device,
            inode=lock.root_inode,
            mode=0o700,
        )
        _verify_state_root_inventory_at(lock.root_descriptor, _ROOT_FIXED_LEAVES)
        plan = _load_prepared_plan(root)
        verify_local_plan(root, plan)
        with _open_journal(root_handle) as journal:
            cursor = load_journal(journal, plan, recover_residues=False)
            remote = _observe_with_local_integrity_priority(
                selected_observer, plan
            )
            state = classify_remote_state(plan, remote)
            unresolved = cursor.trailing_intent is not None
            reconciliation_eligible = (
                cursor.trailing_reconciliation is not None
            )
            if not unresolved:
                _ensure_cursor_matches_remote(plan, cursor, remote)
            return PublicationStatus(
                plan_sha256=plan.sha256(),
                state_index=state.index,
                state_name=state.name,
                applied_actions=cursor.applied_count,
                unresolved_intent=unresolved,
                reconciliation_eligible=reconciliation_eligible,
                manual_review_required=(
                    unresolved and not reconciliation_eligible
                ),
                complete=(
                    not unresolved
                    and cursor.applied_count == MAX_ACTIONS
                    and state.index == MAX_ACTIONS
                ),
            )


def verify_publication(
    *,
    state_root: pathlib.Path | None = None,
    observer: RemoteObserver | None = None,
    source_environment: Mapping[str, str] | None = None,
    read_runner: github_release.GitHubCommandRunner = capture_stdout,
) -> PublicationStatus:
    status = status_plan(
        state_root=state_root,
        observer=observer,
        source_environment=source_environment,
        read_runner=read_runner,
    )
    _require(status.complete, "stable GitHub publication is not complete")
    return status


def _emit_status(marker: str, status: PublicationStatus) -> None:
    print(
        f"{marker} plan_sha256={status.plan_sha256} "
        f"state_index={status.state_index} state={status.state_name} "
        f"applied_actions={status.applied_actions} "
        f"unresolved={str(status.unresolved_intent).lower()} "
        f"reconciliation_eligible="
        f"{str(status.reconciliation_eligible).lower()} "
        f"manual_review_required="
        f"{str(status.manual_review_required).lower()} "
        f"complete={str(status.complete).lower()}"
    )


class _SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        self.exit(
            2,
            "STABLE_GITHUB_USAGE_ERROR error_type=ArgumentError\n",
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _SanitizedArgumentParser(
        description="Coordinate the fixed Apple+platform stable GitHub publication",
        allow_abbrev=False,
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=_SanitizedArgumentParser,
    )
    prepare = commands.add_parser("prepare", allow_abbrev=False)
    prepare.add_argument("expected_results_sha256")
    commands.add_parser("status", allow_abbrev=False)
    publish = commands.add_parser("publish", allow_abbrev=False)
    publish.add_argument("--execute-real-github-mutation", action="store_true")
    publish.add_argument("--expected-plan-sha256", required=True)
    publish.add_argument("--expected-results-sha256", required=True)
    publish.add_argument("--ack-draft-barrier", required=True)
    publish.add_argument("--ack-publication-order", required=True)
    commands.add_parser("verify", allow_abbrev=False)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "prepare":
            plan = prepare_plan(arguments.expected_results_sha256)
            print(
                "STABLE_GITHUB_PREPARED "
                f"plan_sha256={plan.sha256()} results_sha256={plan.results_sha256} "
                f"actions={MAX_ACTIONS} assets={sum(len(r.assets) for r in plan.releases)} "
                f"github_cli_sha256={plan.github_cli_sha256}"
            )
            return 0
        if arguments.command == "status":
            _emit_status("STABLE_GITHUB_STATUS", status_plan())
            return 0
        if arguments.command == "publish":
            _emit_status(
                "STABLE_GITHUB_PUBLISHED",
                publish_plan(
                    execute_real_github_mutation=(
                        arguments.execute_real_github_mutation
                    ),
                    expected_plan_sha256=arguments.expected_plan_sha256,
                    expected_results_sha256=arguments.expected_results_sha256,
                    draft_barrier_ack=arguments.ack_draft_barrier,
                    publication_order_ack=arguments.ack_publication_order,
                ),
            )
            return 0
        _emit_status("STABLE_GITHUB_VERIFIED", verify_publication())
        return 0
    except KeyboardInterrupt:
        print(
            "STABLE_GITHUB_INTERRUPTED error_type=KeyboardInterrupt",
            file=sys.stderr,
        )
        return 130
    except (
        StableGitHubPublicationError,
        github_release.GitHubReleaseObservationError,
        PublicationReceiptIOError,
    ) as exc:
        print(
            f"STABLE_GITHUB_FAILED error_type={type(exc).__name__}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
