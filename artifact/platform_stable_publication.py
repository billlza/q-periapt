#!/usr/bin/env python3
"""Collect the frozen 0.1.0 stable platform publication transaction.

``pending`` turns one verified candidate-attestation projection plus a clean,
annotated-tag verifier checkout into the exact pending domain receipt.
``collect`` promotes that receipt only after stable GitHub metadata, exact
release attestation, bounded fresh downloads, and the tagged checkout's deep
platform-distribution verifier all agree.

GitHub CLI observations use the source-pinned executable with exactly one bounded
caller credential in an otherwise fixed minimal environment and an empty private
CLI configuration.  This collector therefore proves PUBLIC repository/release
metadata and the bytes returned by that authenticated API context; it does not
claim anonymous download availability.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import math
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Never

from bounded_process import (
    BoundedProcessError,
    BoundedResult,
    capture_stdout,
    write_stdout_at,
)
from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    consume_regular_snapshot_at,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import GIT, GitProvenanceError, require_direct_results_only_child
import github_release_observation as github_release
import platform_candidate_attestation as candidate_attestation
from publication_receipt_io import (
    PRIVATE_FILE_MODE,
    PrivateDirectoryHandle,
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    canonical_json_bytes,
    create_private_direct_child_handle,
    create_private_transaction_json,
    ensure_private_safe_root,
    normalize_safe_root,
    open_private_direct_child_handle,
    require_absent_leaf_at,
    read_fixed_json_snapshot,
    verify_exact_directory_inventory_at,
    verify_private_directory_handle_identity,
    write_private_bytes_noreplace_at,
)
from platform_stable_publication_contract import (
    ANDROID_AAR,
    ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
    ANDROID_MANIFEST,
    ANDROID_RUNTIME_BUNDLE,
    ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
    CANDIDATE_PUBLIC_ASSET_NAMES,
    DISTRIBUTION_REVISION,
    PLATFORM_V0_1_0_PUBLICATION_BOUNDARY,
    PlatformV010PublicationContractError,
    PLATFORM_V0_1_0_PUBLICATION_KIND,
    PLATFORM_V0_1_0_PUBLICATION_SCHEMA_VERSION,
    PLATFORM_V0_1_0_STATUS_PENDING,
    PLATFORM_V0_1_0_STATUS_VERIFIED,
    PRODUCT_VERSION,
    PUBLIC_ASSET_NAMES,
    REGISTRY_STATES,
    RELEASE_MANIFEST,
    RELEASE_SUMS,
    RELEASE_TAG,
    RELEASE_URL,
    TAG_SUBJECT_URI,
    parse_utc_timestamp,
    validate_v0_1_0_publication_receipt,
)


REPOSITORY = "billlza/q-periapt"
GH_REPOSITORY_ARGUMENT = f"github.com/{REPOSITORY}"
REPOSITORY_URL = f"https://github.com/{REPOSITORY}"
API_ASSET_PREFIX = f"https://api.github.com/repos/{REPOSITORY}/releases/assets/"
RELEASE_DOWNLOAD_PREFIX = f"{REPOSITORY_URL}/releases/download/"
RELEASE_REF = f"refs/tags/{RELEASE_TAG}"

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLATFORM_PUBLICATION_RECEIPT_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-publication-receipts"
)
PLATFORM_PUBLICATION_VERIFICATION_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-publication-verification"
)
PLATFORM_PUBLICATION_RAW_ROOT = PLATFORM_PUBLICATION_VERIFICATION_ROOT / "raw"
PLATFORM_PUBLICATION_DOWNLOAD_ROOT = (
    PLATFORM_PUBLICATION_VERIFICATION_ROOT / "downloads"
)
PLATFORM_PUBLICATION_WORKTREE_ROOT = (
    REPOSITORY_ROOT / "target" / "abi2-platform-publication-worktrees"
)

RECEIPT_NAME = "platform-v0.1.0-publication-receipt.json"
RAW_REPOSITORY_BEFORE_NAME = "repository-view-before.json"
RAW_RELEASE_BEFORE_NAME = "release-view-before.json"
RAW_RELEASE_VERIFY_NAME = "release-verify.json"
RAW_RELEASE_AFTER_NAME = "release-view-after.json"
RAW_REPOSITORY_AFTER_NAME = "repository-view-after.json"
RAW_DEEP_VERIFY_NAME = "deep-distribution-verifier-stdout.txt"
RAW_FRESH_RECORD_NAME = "fresh-download-verification.json"
RAW_NAMES = frozenset(
    {
        RAW_REPOSITORY_BEFORE_NAME,
        RAW_RELEASE_BEFORE_NAME,
        RAW_RELEASE_VERIFY_NAME,
        RAW_RELEASE_AFTER_NAME,
        RAW_REPOSITORY_AFTER_NAME,
        RAW_DEEP_VERIFY_NAME,
        RAW_FRESH_RECORD_NAME,
    }
)

FRESH_RECORD_KIND = "qperiapt.platform_v0_1_0_fresh_download_verification"
FRESH_RECORD_SCHEMA_VERSION = 1
MAX_PRIVATE_JSON_BYTES = 16 * 1024 * 1024
MAX_REPOSITORY_VIEW_BYTES = 1024 * 1024
MAX_RELEASE_VIEW_BYTES = 4 * 1024 * 1024
MAX_RELEASE_VERIFY_BYTES = 16 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOOL_BYTES = 512 * 1024 * 1024
MAX_DEEP_VERIFY_OUTPUT_BYTES = 16 * 1024
GH_TIMEOUT_SECONDS = 120
GIT_TIMEOUT_SECONDS = 30
DEEP_VERIFY_TIMEOUT_SECONDS = 300
DOWNLOAD_TRANSACTION_TIMEOUT_SECONDS = 900

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_DIRECTORY_LEAF = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]*$")
DEEP_VERIFY_PASS = re.compile(
    r"^ABI2_PLATFORM_DISTRIBUTION_VERIFY_PASS "
    r"commit=([0-9a-f]{40}) assets=5\n$"
)


class PlatformV010PublicationError(ValueError):
    """The platform publication transaction violates a local or remote gate."""


class PlatformV010PublicationRetryableError(PlatformV010PublicationError):
    """One explicit remote observation can be retried as a new transaction."""


@dataclasses.dataclass(frozen=True, slots=True)
class SourceObservation:
    canonical_source_tree_sha256: str
    source_parent_commit: str
    tag_commit: str
    tag_object: str
    tag_tree: str
    verifier_commit: str

    def document(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class AndroidVerificationTools:
    llvm_nm: pathlib.Path
    llvm_readelf: pathlib.Path
    apksigner: pathlib.Path
    zipalign: pathlib.Path

    def ordered(self) -> tuple[tuple[str, pathlib.Path], ...]:
        return (
            ("llvm_nm", self.llvm_nm),
            ("llvm_readelf", self.llvm_readelf),
            ("apksigner", self.apksigner),
            ("zipalign", self.zipalign),
        )


CaptureRunner = Callable[..., BoundedResult]
SinkRunner = Callable[..., BoundedResult]
Clock = Callable[[], dt.datetime]
MonotonicClock = Callable[[], float]
SourceInspector = Callable[..., SourceObservation]


def _fail(message: str) -> Never:
    raise PlatformV010PublicationError(message)


def _retryable(reason: str) -> Never:
    raise PlatformV010PublicationRetryableError(f"retryable:{reason}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        f"{label} must be a JSON object with string keys",
    )
    return value


def _canonical_pretty_json(value: object) -> bytes:
    try:
        return canonical_json_bytes(value)
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _private_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError("private platform publication file metadata differs")


def _read_private_snapshot_at(
    directory: PrivateDirectoryHandle,
    name: str,
    *,
    maximum: int,
    label: str,
) -> FileSnapshot:
    chunks: list[bytes] = []
    try:
        digest = consume_regular_snapshot_at(
            directory.descriptor,
            name,
            display_path=directory.path / name,
            maximum=maximum,
            label=label,
            consume=chunks.append,
            validate_metadata=_private_file_metadata,
        )
    except EvidenceIOError as exc:
        raise PlatformV010PublicationError(
            f"cannot safely read {label}"
        ) from exc
    data = b"".join(chunks)
    _require(
        len(data) == digest.size,
        f"{label} consumer byte count changed unexpectedly",
    )
    return FileSnapshot(
        path=digest.path,
        data=data,
        size=digest.size,
        sha256=digest.sha256,
    )


def _normalized_safe_root(
    safe_root: pathlib.Path, *, label: str
) -> pathlib.Path:
    try:
        return normalize_safe_root(safe_root, label=f"{label} safe root")
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _ensure_platform_safe_roots() -> None:
    """Bootstrap only the module-owned 0700 roots below owned safe parents."""

    ordered = (
        (PLATFORM_PUBLICATION_RECEIPT_ROOT, "platform publication receipt root"),
        (
            PLATFORM_PUBLICATION_VERIFICATION_ROOT,
            "platform publication verification root",
        ),
        (PLATFORM_PUBLICATION_RAW_ROOT, "platform publication raw root"),
        (
            PLATFORM_PUBLICATION_DOWNLOAD_ROOT,
            "platform publication download root",
        ),
        (PLATFORM_PUBLICATION_WORKTREE_ROOT, "platform publication worktree root"),
    )
    for root, label in ordered:
        try:
            ensure_private_safe_root(root, label=label)
        except PublicationReceiptIOError as exc:
            raise PlatformV010PublicationError(str(exc)) from exc


def _normalize_direct_child(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    label: str,
    must_exist: bool,
) -> pathlib.Path:
    _require(path.is_absolute(), f"{label} must be absolute")
    _require(
        all(part not in {"", ".", ".."} for part in path.parts[1:]),
        f"{label} must be canonically spelled",
    )
    root = _normalized_safe_root(safe_root, label=label)
    supplied = os.fspath(path)
    normalized_text = os.path.realpath(supplied)
    root_prefix = os.fspath(root) + os.sep
    if not normalized_text.startswith(root_prefix):
        raise PlatformV010PublicationError(
            f"{label} must remain below its fixed safe root"
        )
    _require(
        normalized_text == os.path.abspath(supplied),
        f"{label} must contain no symlink or traversal aliases",
    )
    normalized = pathlib.Path(normalized_text)
    _require(normalized.parent == root, f"{label} must be a direct safe-root child")
    _require(
        SAFE_DIRECTORY_LEAF.fullmatch(normalized.name) is not None,
        f"{label} leaf is unsafe",
    )
    try:
        metadata = normalized.lstat()
    except FileNotFoundError:
        _require(not must_exist, f"{label} does not exist")
        return normalized
    except OSError as exc:
        raise PlatformV010PublicationError(f"cannot inspect {label}") from exc
    _require(must_exist, f"{label} already exists")
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and not normalized.is_symlink()
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        f"{label} is not an owned mode-0700 non-symlink directory",
    )
    return normalized


def _write_receipt(
    receipt: dict[str, object], *, transaction_prefix: str
) -> tuple[pathlib.Path, str]:
    try:
        validate_v0_1_0_publication_receipt(receipt)
    except PlatformV010PublicationContractError as exc:
        raise PlatformV010PublicationError(
            "platform publication receipt violates its domain contract: "
            f"{exc}"
        ) from exc
    try:
        return create_private_transaction_json(
            safe_root=PLATFORM_PUBLICATION_RECEIPT_ROOT,
            transaction_prefix=transaction_prefix,
            expected_leaf=RECEIPT_NAME,
            value=receipt,
            label="platform publication receipt",
            maximum=MAX_PRIVATE_JSON_BYTES,
        )
    except PublicationReceiptCommittedError:
        raise
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _system_clock() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _utc_now(
    clock: Clock, *, label: str, not_before: Sequence[dt.datetime]
) -> str:
    observed = clock()
    _require(
        isinstance(observed, dt.datetime)
        and observed.tzinfo is not None
        and observed.utcoffset() is not None,
        f"{label} clock must return a timezone-aware datetime",
    )
    normalized = observed.astimezone(dt.UTC).replace(microsecond=0)
    _require(
        all(boundary <= normalized for boundary in not_before),
        f"{label} predates already-observed evidence",
    )
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _contract_timestamp(value: object, label: str) -> dt.datetime:
    try:
        return parse_utc_timestamp(value, label)
    except PlatformV010PublicationContractError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _git_environment(source: Mapping[str, str]) -> dict[str, str]:
    overridden = sorted(name for name in source if name.startswith("GIT_"))
    _require(
        not overridden,
        "platform publication rejects caller Git environment overrides",
    )
    return github_release.git_observation_environment()


def _raise_github_execution_error(
    error: github_release.GitHubReleaseObservationError,
    *,
    unavailable_marker: str,
    nonzero_marker: str,
) -> Never:
    if isinstance(error, github_release.GitHubCliExecutionError):
        if error.error_kind in {"timeout", "io", "reap"}:
            _retryable(unavailable_marker)
        if error.returncode == 1:
            _retryable(nonzero_marker)
    raise PlatformV010PublicationError(str(error)) from error


def _capture_command(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: CaptureRunner,
    remote: bool,
    require_output: bool = True,
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
        if remote and exc.kind in {"timeout", "io", "reap"}:
            _retryable("github-observation-unavailable")
        raise PlatformV010PublicationError(f"{label} failed safely") from exc
    if result.returncode != 0:
        if remote and result.returncode == 1:
            _retryable("github-command-nonzero")
        _fail(f"{label} was rejected")
    if require_output:
        _require(result.stdout, f"{label} returned empty output")
    return result.stdout


def _git_base(git: str, verifier: pathlib.Path) -> list[str]:
    return [
        git,
        "-C",
        str(verifier),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
    ]


def _git_bytes(
    git: str,
    verifier: pathlib.Path,
    arguments: Sequence[str],
    *,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: CaptureRunner,
) -> bytes:
    return _capture_command(
        [*_git_base(git, verifier), *arguments],
        timeout_seconds=GIT_TIMEOUT_SECONDS,
        maximum_bytes=maximum_bytes,
        environment=environment,
        label=label,
        runner=runner,
        remote=False,
        require_output=False,
    )


def _git_line(
    git: str,
    verifier: pathlib.Path,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    label: str,
    runner: CaptureRunner,
) -> str:
    raw = _git_bytes(
        git,
        verifier,
        arguments,
        maximum_bytes=1024,
        environment=environment,
        label=label,
        runner=runner,
    )
    try:
        value = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PlatformV010PublicationError(f"{label} is not ASCII") from exc
    _require(value.endswith("\n") and value.count("\n") == 1, f"{label} differs")
    return value[:-1]


def _normalize_verifier_checkout(path: pathlib.Path) -> pathlib.Path:
    verifier = _normalize_direct_child(
        path,
        safe_root=PLATFORM_PUBLICATION_WORKTREE_ROOT,
        label="platform verifier checkout",
        must_exist=True,
    )
    git_directory = verifier / ".git"
    try:
        metadata = git_directory.lstat()
    except OSError as exc:
        raise PlatformV010PublicationError(
            "platform verifier checkout lacks a .git directory"
        ) from exc
    _require(
        stat.S_ISDIR(metadata.st_mode) and not git_directory.is_symlink(),
        "platform verifier checkout requires a non-symlink .git directory",
    )
    return verifier


def inspect_verifier_source(
    verifier_checkout: pathlib.Path,
    *,
    git: str,
    environment: Mapping[str, str],
    runner: CaptureRunner,
) -> SourceObservation:
    """Observe one clean annotated-tag checkout before any release claim."""

    verifier = _normalize_verifier_checkout(verifier_checkout)

    def metadata_snapshot() -> tuple[str, str, str, str, str, bytes]:
        tag_type = _git_line(
            git,
            verifier,
            ["cat-file", "-t", RELEASE_REF],
            environment=environment,
            label="platform release tag type",
            runner=runner,
        )
        tag_object = _git_line(
            git,
            verifier,
            ["rev-parse", "--verify", RELEASE_REF],
            environment=environment,
            label="platform release tag object",
            runner=runner,
        )
        tag_commit = _git_line(
            git,
            verifier,
            ["rev-parse", "--verify", f"{RELEASE_REF}^{{commit}}"],
            environment=environment,
            label="platform release tag commit",
            runner=runner,
        )
        tag_tree = _git_line(
            git,
            verifier,
            ["rev-parse", "--verify", f"{RELEASE_REF}^{{tree}}"],
            environment=environment,
            label="platform release tag tree",
            runner=runner,
        )
        head = _git_line(
            git,
            verifier,
            ["rev-parse", "--verify", "HEAD^{commit}"],
            environment=environment,
            label="platform verifier HEAD",
            runner=runner,
        )
        parent_line = _git_line(
            git,
            verifier,
            ["rev-list", "--parents", "-n", "1", head],
            environment=environment,
            label="platform results-only parent line",
            runner=runner,
        )
        status = _git_bytes(
            git,
            verifier,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            maximum_bytes=1024 * 1024,
            environment=environment,
            label="platform verifier status",
            runner=runner,
        )
        _require(tag_type == "tag", "platform release tag is not annotated")
        _require(
            all(
                HEX_40.fullmatch(value) is not None
                for value in (tag_object, tag_commit, tag_tree, head)
            ),
            "platform verifier Git identity is malformed",
        )
        _require(tag_object != tag_commit, "platform release tag is not annotated")
        _require(
            head == tag_commit,
            "platform verifier checkout is not at the release tag",
        )
        parent_fields = parent_line.split(" ")
        _require(
            len(parent_fields) == 2
            and parent_fields[0] == head
            and HEX_40.fullmatch(parent_fields[1]) is not None,
            "platform tag commit must have exactly one source parent",
        )
        _require(status == b"", "platform verifier checkout is dirty")
        return tag_object, tag_commit, tag_tree, head, parent_fields[1], status

    before = metadata_snapshot()
    try:
        require_direct_results_only_child(
            verifier,
            before[4],
            before[1],
        )
    except GitProvenanceError as exc:
        raise PlatformV010PublicationError(
            "platform tag commit is not the direct results-only child"
        ) from exc
    try:
        results_snapshot = read_regular_snapshot(
            verifier / "artifact" / "results.json",
            maximum=MAX_PRIVATE_JSON_BYTES,
            label="tagged platform results manifest",
        )
        results_value = parse_strict_json_bytes(
            results_snapshot.data,
            label="tagged platform results manifest",
        )
    except EvidenceIOError as exc:
        raise PlatformV010PublicationError(
            "cannot read the tagged platform results manifest"
        ) from exc
    results = _object(results_value, "tagged platform results manifest")
    provenance = _object(
        results.get("provenance"), "tagged platform results provenance"
    )
    declared_source_parent = provenance.get("snapshot_commit")
    declared_source_digest = results.get("proof_source_tree_sha256")
    _require(
        isinstance(declared_source_parent, str)
        and HEX_40.fullmatch(declared_source_parent) is not None
        and isinstance(declared_source_digest, str)
        and HEX_64.fullmatch(declared_source_digest) is not None,
        "tagged platform results source identity is malformed",
    )
    try:
        source_digest = canonical_tree_digest(
            verifier, repository_paths(verifier)
        )
    except (LedgerError, ValueError) as exc:
        raise PlatformV010PublicationError(
            "cannot compute the platform verifier canonical source digest"
        ) from exc
    _require(
        source_digest == declared_source_digest,
        "platform verifier canonical source digest differs from results",
    )
    after = metadata_snapshot()
    _require(
        after == before,
        "platform verifier checkout changed during source observation",
    )
    tag_object, tag_commit, tag_tree, head, source_parent_commit, _status = before
    _require(
        declared_source_parent == source_parent_commit,
        "platform results provenance differs from the tag commit parent",
    )
    return SourceObservation(
        canonical_source_tree_sha256=source_digest,
        source_parent_commit=source_parent_commit,
        tag_commit=tag_commit,
        tag_object=tag_object,
        tag_tree=tag_tree,
        verifier_commit=head,
    )


def _load_candidate_projection(path: pathlib.Path) -> dict[str, Any]:
    try:
        return read_fixed_json_snapshot(
            path,
            safe_root=candidate_attestation.CANDIDATE_PROJECTION_ROOT,
            expected_leaf=candidate_attestation.PROJECTION_NAME,
            label="candidate attestation projection",
            parent_depth=1,
            maximum=MAX_PRIVATE_JSON_BYTES,
            file_mode=PRIVATE_FILE_MODE,
        ).value
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _load_receipt(path: pathlib.Path, *, expected_status: str) -> dict[str, Any]:
    try:
        receipt = read_fixed_json_snapshot(
            path,
            safe_root=PLATFORM_PUBLICATION_RECEIPT_ROOT,
            expected_leaf=RECEIPT_NAME,
            label="platform publication receipt input",
            parent_depth=1,
            maximum=MAX_PRIVATE_JSON_BYTES,
            file_mode=PRIVATE_FILE_MODE,
        ).value
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    try:
        validate_v0_1_0_publication_receipt(receipt)
    except PlatformV010PublicationContractError as exc:
        raise PlatformV010PublicationError(
            "platform publication receipt input violates its domain contract: "
            f"{exc}"
        ) from exc
    _require(
        receipt["status"] == expected_status,
        "platform publication receipt input status differs",
    )
    return receipt


def assemble_pending_receipt(
    candidate_projection: pathlib.Path,
    verifier_checkout: pathlib.Path,
    *,
    runner: CaptureRunner = capture_stdout,
    clock: Clock = _system_clock,
    source_environment: Mapping[str, str] | None = None,
    git_tool: str | None = None,
    source_inspector: SourceInspector = inspect_verifier_source,
) -> tuple[pathlib.Path, str, SourceObservation]:
    """Publish one exact pending receipt without any remote-publication claim."""

    _ensure_platform_safe_roots()
    candidate = _load_candidate_projection(candidate_projection)
    environment = _git_environment(
        os.environ if source_environment is None else source_environment
    )
    _require(
        git_tool is None or git_tool == GIT,
        "platform publication Git executable differs from the fixed system Git",
    )
    source = source_inspector(
        verifier_checkout,
        git=GIT,
        environment=environment,
        runner=runner,
    )
    candidate_verified_at = _contract_timestamp(
        candidate.get("verified_at"), "candidate projection verified_at"
    )
    observed_at = _utc_now(
        clock,
        label="platform pending observation",
        not_before=(candidate_verified_at,),
    )
    receipt: dict[str, object] = {
        "boundary": PLATFORM_V0_1_0_PUBLICATION_BOUNDARY,
        "identity": {
            "distribution_revision": DISTRIBUTION_REVISION,
            "product_version": PRODUCT_VERSION,
            "release_tag": RELEASE_TAG,
            "release_url": RELEASE_URL,
        },
        "kind": PLATFORM_V0_1_0_PUBLICATION_KIND,
        "observation": {
            "candidate_attestation": candidate,
            "observed_at": observed_at,
            "source": source.document(),
        },
        "schema_version": PLATFORM_V0_1_0_PUBLICATION_SCHEMA_VERSION,
        "status": PLATFORM_V0_1_0_STATUS_PENDING,
    }
    output, digest = _write_receipt(
        receipt, transaction_prefix="transaction.pending."
    )
    return output, digest, source


def _release_policy(
    source: SourceObservation,
    *,
    release_id: int | None,
    asset_sha256: Mapping[str, str] | None,
) -> github_release.ReleasePolicy:
    return github_release.ReleasePolicy(
        repository=REPOSITORY,
        repository_url=REPOSITORY_URL,
        release_url=RELEASE_URL,
        download_prefix=RELEASE_DOWNLOAD_PREFIX,
        api_asset_prefix=API_ASSET_PREFIX,
        tag_subject_uri=TAG_SUBJECT_URI,
        tag=RELEASE_TAG,
        tag_commit=source.tag_commit,
        tag_object=source.tag_object,
        asset_names=PUBLIC_ASSET_NAMES,
        expected_prerelease=False,
        expected_release_id=release_id,
        expected_sha256=asset_sha256,
        expected_content_types=None,
        require_asset_order=False,
    )


def _write_raw(
    raw_directory: PrivateDirectoryHandle,
    name: str,
    data: bytes,
    *,
    label: str,
) -> str:
    try:
        return write_private_bytes_noreplace_at(
            raw_directory.descriptor,
            name,
            data,
            label=label,
            maximum=MAX_RELEASE_VERIFY_BYTES,
        )
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def _read_raw(
    raw_directory: PrivateDirectoryHandle,
    name: str,
    *,
    maximum: int,
    label: str,
) -> bytes:
    return _read_private_snapshot_at(
        raw_directory,
        name,
        maximum=maximum,
        label=label,
    ).data


def _observe_remote_json(
    tool: github_release.GitHubCliIdentity,
    arguments: Sequence[str],
    *,
    raw_directory: PrivateDirectoryHandle,
    raw_name: str,
    maximum_bytes: int,
    environment: Mapping[str, str],
    label: str,
    runner: CaptureRunner,
) -> bytes:
    try:
        raw = github_release.capture_github_cli(
            tool,
            arguments,
            timeout_seconds=GH_TIMEOUT_SECONDS,
            maximum_bytes=maximum_bytes,
            environment=environment,
            label=label,
            runner=runner,
        )
    except github_release.GitHubReleaseObservationError as exc:
        _raise_github_execution_error(
            exc,
            unavailable_marker="github-observation-unavailable",
            nonzero_marker="github-command-nonzero",
        )
    _write_raw(raw_directory, raw_name, raw, label=f"raw {label}")
    return _read_raw(
        raw_directory,
        raw_name,
        maximum=maximum_bytes,
        label=f"raw {label}",
    )


def _remaining_download_timeout(deadline: float, monotonic: MonotonicClock) -> int:
    remaining = deadline - monotonic()
    if remaining <= 0:
        _retryable("github-download-deadline-exhausted")
    return min(300, max(1, math.ceil(remaining)))


def _download_asset(
    github_cli: github_release.GitHubCliIdentity,
    name: str,
    expected: Mapping[str, object],
    *,
    index: int,
    download_directory: PrivateDirectoryHandle,
    deadline: float,
    environment: Mapping[str, str],
    runner: SinkRunner,
    monotonic: MonotonicClock,
) -> FileSnapshot:
    expected_size = expected["bytes"]
    expected_sha256 = expected["sha256"]
    _require(
        type(expected_size) is int and 0 < expected_size <= MAX_ASSET_BYTES,
        f"GitHub release asset size is out of policy for {name}",
    )
    _require(
        isinstance(expected_sha256, str)
        and HEX_64.fullmatch(expected_sha256) is not None,
        f"GitHub release asset digest is malformed for {name}",
    )
    temporary_name = f"download-{index:02d}.tmp"
    require_absent_leaf_at(
        download_directory.descriptor,
        temporary_name,
        label=f"temporary download for {name}",
    )
    require_absent_leaf_at(
        download_directory.descriptor,
        name,
        label=f"fresh download for {name}",
    )
    try:
        github_release.write_github_cli_stdout_at(
            github_cli,
            [
                "release",
                "download",
                RELEASE_TAG,
                "--repo",
                GH_REPOSITORY_ARGUMENT,
                "--pattern",
                name,
                "--output",
                "-",
            ],
            output_directory_fd=download_directory.descriptor,
            output_name=temporary_name,
            timeout_seconds=_remaining_download_timeout(deadline, monotonic),
            maximum_bytes=expected_size,
            environment=environment,
            label=f"GitHub download for {name}",
            runner=runner,
        )
    except github_release.GitHubReleaseObservationError as exc:
        _raise_github_execution_error(
            exc,
            unavailable_marker="github-download-unavailable",
            nonzero_marker="github-download-nonzero",
        )
    temporary = _read_private_snapshot_at(
        download_directory,
        temporary_name,
        maximum=expected_size,
        label=f"temporary fresh download for {name}",
    )
    _require(
        temporary.size == expected_size and temporary.sha256 == expected_sha256,
        f"fresh download size or digest differs for {name}",
    )
    require_absent_leaf_at(
        download_directory.descriptor,
        name,
        label=f"fresh download for {name}",
    )
    try:
        os.link(
            temporary_name,
            name,
            src_dir_fd=download_directory.descriptor,
            dst_dir_fd=download_directory.descriptor,
            follow_symlinks=False,
        )
        os.fsync(download_directory.descriptor)
        os.unlink(temporary_name, dir_fd=download_directory.descriptor)
        os.fsync(download_directory.descriptor)
    except FileExistsError as exc:
        raise PlatformV010PublicationError(
            f"fresh download already exists for {name}"
        ) from exc
    except OSError as exc:
        raise PlatformV010PublicationError(
            f"cannot exclusively publish fresh download for {name}"
        ) from exc
    return _read_private_snapshot_at(
        download_directory,
        name,
        maximum=expected_size,
        label=f"fresh download for {name}",
    )


def _inventory_fresh_downloads(
    directory: PrivateDirectoryHandle,
    expected_assets: Mapping[str, Mapping[str, object]],
) -> dict[str, FileSnapshot]:
    expected_names = frozenset(PUBLIC_ASSET_NAMES)
    snapshots: dict[str, FileSnapshot] = {}
    try:
        verify_exact_directory_inventory_at(
            directory.descriptor,
            expected_names,
            label="fresh platform download directory before snapshot",
        )
        for name in PUBLIC_ASSET_NAMES:
            expected_size = expected_assets[name]["bytes"]
            _require(
                type(expected_size) is int and expected_size > 0,
                f"fresh platform download size is invalid for {name}",
            )
            snapshot = _read_private_snapshot_at(
                directory,
                name,
                maximum=expected_size,
                label=f"fresh platform download {name}",
            )
            _require(
                snapshot.size == expected_size
                and snapshot.sha256 == expected_assets[name]["sha256"],
                f"fresh platform download bytes differ for {name}",
            )
            snapshots[name] = snapshot
        verify_exact_directory_inventory_at(
            directory.descriptor,
            expected_names,
            label="fresh platform download directory after snapshot",
        )
    except (EvidenceIOError, PublicationReceiptIOError) as exc:
        raise PlatformV010PublicationError(
            "cannot safely inventory fresh platform downloads"
        ) from exc
    return snapshots


def _normalize_android_tools(tools: AndroidVerificationTools) -> AndroidVerificationTools:
    normalized: dict[str, pathlib.Path] = {}
    for label, path in tools.ordered():
        _require(path.is_absolute(), f"Android {label} path must be absolute")
        supplied = os.path.abspath(os.fspath(path))
        resolved_text = os.path.realpath(supplied)
        _require(resolved_text == supplied, f"Android {label} path must be canonical")
        resolved = pathlib.Path(resolved_text)
        try:
            metadata = resolved.lstat()
        except OSError as exc:
            raise PlatformV010PublicationError(
                f"cannot inspect Android {label} tool"
            ) from exc
        _require(
            stat.S_ISREG(metadata.st_mode)
            and not resolved.is_symlink()
            and os.access(resolved, os.X_OK),
            f"Android {label} tool is not an executable regular file",
        )
        normalized[label] = resolved
    return AndroidVerificationTools(**normalized)


def _run_deep_distribution_verifier(
    verifier_checkout: pathlib.Path,
    download_directory: pathlib.Path,
    tools: AndroidVerificationTools,
    *,
    download_directory_handle: PrivateDirectoryHandle,
    expected_commit: str,
    environment: Mapping[str, str],
    runner: CaptureRunner,
) -> tuple[dict[str, Any], bytes]:
    verifier = _normalize_verifier_checkout(verifier_checkout)
    script = verifier / "artifact" / "python-run.sh"
    module = verifier / "artifact" / "platform_distribution.py"
    for path, label in ((script, "tagged Python runner"), (module, "tagged platform verifier")):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise PlatformV010PublicationError(f"cannot inspect {label}") from exc
        _require(
            stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"{label} must be a non-symlink regular file",
        )
    stdout = _capture_command(
        [
            "/bin/sh",
            str(script),
            "artifact/platform_distribution.py",
            "verify",
            "--root",
            str(verifier),
            "--release-dir",
            str(download_directory),
            "--android-llvm-nm",
            str(tools.llvm_nm),
            "--android-llvm-readelf",
            str(tools.llvm_readelf),
            "--android-apksigner",
            str(tools.apksigner),
            "--android-zipalign",
            str(tools.zipalign),
        ],
        timeout_seconds=DEEP_VERIFY_TIMEOUT_SECONDS,
        maximum_bytes=MAX_DEEP_VERIFY_OUTPUT_BYTES,
        environment=environment,
        label="tagged platform deep distribution verifier",
        runner=runner,
        remote=False,
    )
    try:
        text = stdout.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PlatformV010PublicationError(
            "tagged platform deep verifier output is not ASCII"
        ) from exc
    match = DEEP_VERIFY_PASS.fullmatch(text)
    _require(match is not None, "tagged platform deep verifier PASS marker differs")
    _require(match.group(1) == expected_commit, "tagged platform deep verifier commit differs")
    manifest_snapshot = _read_private_snapshot_at(
        download_directory_handle,
        RELEASE_MANIFEST,
        maximum=MAX_PRIVATE_JSON_BYTES,
        label="fresh platform distribution manifest",
    )
    try:
        manifest = parse_strict_json_bytes(
            manifest_snapshot.data,
            label="fresh platform distribution manifest",
        )
    except EvidenceIOError as exc:
        raise PlatformV010PublicationError(
            "fresh platform distribution manifest is not strict JSON"
        ) from exc
    _require(
        isinstance(manifest, dict)
        and all(isinstance(key, str) for key in manifest),
        "fresh platform distribution manifest root differs",
    )
    return manifest, stdout


def _runtime_projection(
    manifest: Mapping[str, object],
    assets: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    values = manifest.get("assets")
    _require(isinstance(values, list), "deep platform manifest assets are missing")
    records: dict[str, dict[str, Any]] = {}
    for value in values:
        record = _object(value, "deep platform manifest asset")
        name = record.get("name")
        _require(
            isinstance(name, str) and name not in records,
            "deep platform manifest asset names differ",
        )
        records[name] = record
    _require(
        ANDROID_RUNTIME_BUNDLE in records
        and ANDROID_AAR in records
        and ANDROID_MANIFEST in records,
        "deep platform manifest lacks Android release records",
    )
    runtime = records[ANDROID_RUNTIME_BUNDLE]
    device = _object(runtime.get("device"), "deep Android runtime device")
    return {
        "bundle_manifest_sha256": runtime.get("bundle_manifest_sha256"),
        "bundle_schema": ANDROID_RUNTIME_BUNDLE_SCHEMA_VERSION,
        "bundle_sha256": assets[ANDROID_RUNTIME_BUNDLE]["sha256"],
        "device_abi": device.get("abi"),
        "device_kind": device.get("kind"),
        "device_sdk": device.get("sdk"),
        "page_size": device.get("page_size"),
        "proof_schema": ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "proof_sha256": runtime.get("proof_sha256"),
        "release_mode": True,
        "tested_aar_manifest_sha256": assets[ANDROID_MANIFEST]["sha256"],
        "tested_aar_sha256": runtime.get("tested_aar_sha256"),
    }


def _tool_record(tools: AndroidVerificationTools) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for label, path in tools.ordered():
        try:
            snapshot = read_regular_snapshot(
                path, maximum=MAX_TOOL_BYTES, label=f"Android {label} tool"
            )
        except EvidenceIOError as exc:
            raise PlatformV010PublicationError(
                f"cannot snapshot Android {label} tool"
            ) from exc
        records[label] = {"name": path.name, "sha256": snapshot.sha256}
    return records


def _validate_raw_directory(
    raw_directory: PrivateDirectoryHandle,
    expected_sha256: Mapping[str, str],
) -> None:
    _require(
        frozenset(expected_sha256) == RAW_NAMES,
        "platform publication raw digest set differs",
    )
    try:
        verify_exact_directory_inventory_at(
            raw_directory.descriptor,
            RAW_NAMES,
            label="platform publication raw directory before resample",
        )
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    for name in RAW_NAMES:
        raw = _read_raw(
            raw_directory,
            name,
            maximum=MAX_RELEASE_VERIFY_BYTES,
            label=f"platform publication raw file {name}",
        )
        _require(
            hashlib.sha256(raw).hexdigest() == expected_sha256[name],
            f"platform publication raw bytes changed for {name}",
        )
    try:
        verify_exact_directory_inventory_at(
            raw_directory.descriptor,
            RAW_NAMES,
            label="platform publication raw directory after resample",
        )
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc


def collect_verified_receipt(
    pending_receipt: pathlib.Path,
    verifier_checkout: pathlib.Path,
    raw_directory: pathlib.Path,
    download_directory: pathlib.Path,
    *,
    android_tools: AndroidVerificationTools,
    runner: CaptureRunner = capture_stdout,
    sink_runner: SinkRunner = write_stdout_at,
    clock: Clock = _system_clock,
    monotonic: MonotonicClock = time.monotonic,
    source_environment: Mapping[str, str] | None = None,
    git_tool: str | None = None,
    source_inspector: SourceInspector = inspect_verifier_source,
    deep_verifier: Callable[..., tuple[dict[str, Any], bytes]] = _run_deep_distribution_verifier,
) -> tuple[pathlib.Path, str, int]:
    """Collect one promotion while every mutable transaction directory is pinned."""

    _ensure_platform_safe_roots()
    receipt = _load_receipt(
        pending_receipt,
        expected_status=PLATFORM_V0_1_0_STATUS_PENDING,
    )
    verifier = _normalize_verifier_checkout(verifier_checkout)
    raw = _normalize_direct_child(
        raw_directory,
        safe_root=PLATFORM_PUBLICATION_RAW_ROOT,
        label="platform publication raw directory",
        must_exist=False,
    )
    downloads = _normalize_direct_child(
        download_directory,
        safe_root=PLATFORM_PUBLICATION_DOWNLOAD_ROOT,
        label="fresh platform download directory",
        must_exist=False,
    )
    _require(raw != downloads, "platform publication transaction directories overlap")
    try:
        with contextlib.ExitStack() as resources:
            verifier_handle = resources.enter_context(
                open_private_direct_child_handle(
                    safe_root=PLATFORM_PUBLICATION_WORKTREE_ROOT,
                    direct_child_name=verifier.name,
                    label="platform verifier checkout",
                )
            )
            raw_handle = resources.enter_context(
                create_private_direct_child_handle(
                    safe_root=PLATFORM_PUBLICATION_RAW_ROOT,
                    direct_child_name=raw.name,
                    label="platform publication raw directory",
                )
            )
            download_handle = resources.enter_context(
                create_private_direct_child_handle(
                    safe_root=PLATFORM_PUBLICATION_DOWNLOAD_ROOT,
                    direct_child_name=downloads.name,
                    label="fresh platform download directory",
                )
            )
            verified_receipt, release_id = _collect_verified_receipt_pinned(
                receipt,
                verifier_handle,
                raw_handle,
                download_handle,
                android_tools=android_tools,
                runner=runner,
                sink_runner=sink_runner,
                clock=clock,
                monotonic=monotonic,
                source_environment=source_environment,
                git_tool=git_tool,
                source_inspector=source_inspector,
                deep_verifier=deep_verifier,
            )
    except PublicationReceiptIOError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    output, digest = _write_receipt(
        verified_receipt,
        transaction_prefix="transaction.verified.",
    )
    return output, digest, release_id


def _collect_verified_receipt_pinned(
    receipt: dict[str, Any],
    verifier: PrivateDirectoryHandle,
    raw: PrivateDirectoryHandle,
    downloads: PrivateDirectoryHandle,
    *,
    android_tools: AndroidVerificationTools,
    runner: CaptureRunner = capture_stdout,
    sink_runner: SinkRunner = write_stdout_at,
    clock: Clock = _system_clock,
    monotonic: MonotonicClock = time.monotonic,
    source_environment: Mapping[str, str] | None = None,
    git_tool: str | None = None,
    source_inspector: SourceInspector = inspect_verifier_source,
    deep_verifier: Callable[..., tuple[dict[str, Any], bytes]] = _run_deep_distribution_verifier,
) -> tuple[dict[str, object], int]:
    """Collect one fail-closed pending-to-verified publication promotion."""

    source = os.environ if source_environment is None else source_environment
    git_environment = _git_environment(source)
    try:
        github_environment = github_release.github_cli_environment(source)
        github_cli = github_release.select_github_cli()
    except github_release.GitHubReleaseObservationError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    _require(
        git_tool is None or git_tool == GIT,
        "platform publication Git executable differs from the fixed system Git",
    )
    tools = _normalize_android_tools(android_tools)

    def verify_transaction_handles() -> None:
        for handle, label in (
            (verifier, "platform verifier checkout"),
            (raw, "platform publication raw directory"),
            (downloads, "fresh platform download directory"),
        ):
            try:
                verify_private_directory_handle_identity(handle, label=label)
            except PublicationReceiptIOError as exc:
                raise PlatformV010PublicationError(str(exc)) from exc

    verify_transaction_handles()
    source_before = source_inspector(
        verifier.path,
        git=GIT,
        environment=git_environment,
        runner=runner,
    )
    pending_observation = _object(receipt["observation"], "pending platform observation")
    _require(
        source_before.document() == pending_observation["source"],
        "platform verifier source differs from the pending receipt",
    )
    verify_transaction_handles()
    raw_sha256: dict[str, str] = {}

    repository_arguments = [
        "repo",
        "view",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(github_release.REPOSITORY_VIEW_FIELDS),
    ]
    release_arguments = [
        "release",
        "view",
        RELEASE_TAG,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--json",
        ",".join(github_release.RELEASE_VIEW_FIELDS),
    ]
    verify_arguments = [
        "release",
        "verify",
        RELEASE_TAG,
        "--repo",
        GH_REPOSITORY_ARGUMENT,
        "--format",
        "json",
    ]
    repository_policy = github_release.RepositoryPolicy(
        repository=REPOSITORY, repository_url=REPOSITORY_URL
    )
    repository_before_raw = _observe_remote_json(
        github_cli,
        repository_arguments,
        raw_directory=raw,
        raw_name=RAW_REPOSITORY_BEFORE_NAME,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=github_environment,
        label="GitHub platform repository view-before",
        runner=runner,
    )
    raw_sha256[RAW_REPOSITORY_BEFORE_NAME] = hashlib.sha256(
        repository_before_raw
    ).hexdigest()
    try:
        repository_before = github_release.parse_repository_view(
            repository_before_raw,
            policy=repository_policy,
            label="GitHub platform repository view-before",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    release_before_raw = _observe_remote_json(
        github_cli,
        release_arguments,
        raw_directory=raw,
        raw_name=RAW_RELEASE_BEFORE_NAME,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=github_environment,
        label="GitHub platform release view-before",
        runner=runner,
    )
    raw_sha256[RAW_RELEASE_BEFORE_NAME] = hashlib.sha256(
        release_before_raw
    ).hexdigest()
    try:
        release_before = github_release.parse_release_view(
            release_before_raw,
            policy=_release_policy(
                source_before, release_id=None, asset_sha256=None
            ),
            label="GitHub platform release view-before",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    assets = {asset["name"]: asset for asset in release_before.assets}
    _require(
        all(
            type(assets[name]["bytes"]) is int
            and 0 < assets[name]["bytes"] <= MAX_ASSET_BYTES
            for name in PUBLIC_ASSET_NAMES
        )
        and sum(assets[name]["bytes"] for name in PUBLIC_ASSET_NAMES)
        <= MAX_TOTAL_ASSET_BYTES,
        "GitHub platform release asset sizes exceed the bounded download policy",
    )
    candidate_projection = _object(
        pending_observation["candidate_attestation"],
        "pending candidate attestation",
    )
    candidate_subjects = {
        subject["name"]: subject["digest"]["sha256"]
        for subject in candidate_projection["subjects"]
    }
    for name in CANDIDATE_PUBLIC_ASSET_NAMES:
        _require(
            candidate_subjects[name] == assets[name]["sha256"],
            f"candidate/public GitHub asset digest differs for {name}",
        )

    verify_raw = _observe_remote_json(
        github_cli,
        verify_arguments,
        raw_directory=raw,
        raw_name=RAW_RELEASE_VERIFY_NAME,
        maximum_bytes=MAX_RELEASE_VERIFY_BYTES,
        environment=github_environment,
        label="GitHub platform release verification",
        runner=runner,
    )
    raw_sha256[RAW_RELEASE_VERIFY_NAME] = hashlib.sha256(verify_raw).hexdigest()
    expected_hashes = {name: assets[name]["sha256"] for name in PUBLIC_ASSET_NAMES}
    policy = _release_policy(
        source_before,
        release_id=release_before.release_id,
        asset_sha256=expected_hashes,
    )
    try:
        release_verification = github_release.parse_release_verification(
            verify_raw,
            policy=policy,
            release_id=release_before.release_id,
            published_at=release_before.published_at,
            label="GitHub platform release verification",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc

    tool_record_before = _tool_record(tools)
    deadline = monotonic() + DOWNLOAD_TRANSACTION_TIMEOUT_SECONDS
    downloaded: dict[str, FileSnapshot] = {}
    for index, name in enumerate(PUBLIC_ASSET_NAMES):
        downloaded[name] = _download_asset(
            github_cli,
            name,
            assets[name],
            index=index,
            download_directory=downloads,
            deadline=deadline,
            environment=github_environment,
            runner=sink_runner,
            monotonic=monotonic,
        )
    inventoried = _inventory_fresh_downloads(downloads, assets)
    _require(
        {name: (item.size, item.sha256) for name, item in downloaded.items()}
        == {name: (item.size, item.sha256) for name, item in inventoried.items()},
        "fresh platform downloads changed after publication",
    )
    verify_transaction_handles()
    manifest, deep_stdout = deep_verifier(
        verifier.path,
        downloads.path,
        tools,
        download_directory_handle=downloads,
        expected_commit=source_before.tag_commit,
        environment=git_environment,
        runner=runner,
    )
    verify_transaction_handles()
    tool_record_after = _tool_record(tools)
    _require(
        tool_record_after == tool_record_before,
        "Android verification tools changed during platform deep verification",
    )
    post_deep = _inventory_fresh_downloads(downloads, assets)
    _require(
        {name: (item.size, item.sha256) for name, item in post_deep.items()}
        == {name: (item.size, item.sha256) for name, item in inventoried.items()},
        "fresh platform downloads changed during deep verification",
    )
    raw_sha256[RAW_DEEP_VERIFY_NAME] = _write_raw(
        raw,
        RAW_DEEP_VERIFY_NAME,
        deep_stdout,
        label="raw tagged deep verifier output",
    )
    runtime = _runtime_projection(manifest, assets)
    fresh_verified_at = _utc_now(
        clock,
        label="fresh platform verification",
        not_before=(
            _contract_timestamp(release_before.published_at, "platform published_at"),
            _contract_timestamp(
                release_verification.verified_at,
                "platform release attestation verified_at",
            ),
        ),
    )
    fresh_record: dict[str, object] = {
        "android_tools": tool_record_before,
        "anonymous_availability_verified": False,
        "assets": list(release_before.assets),
        "deep_distribution_verified": True,
        "download_transport": "github_cli_configured_auth_context",
        "kind": FRESH_RECORD_KIND,
        "schema_version": FRESH_RECORD_SCHEMA_VERSION,
        "verified_at": fresh_verified_at,
        "verifier": {
            "clean_annotated_tag_checkout": True,
            "commit": source_before.verifier_commit,
            "release_tag": RELEASE_TAG,
        },
        "verifier_stdout_sha256": hashlib.sha256(deep_stdout).hexdigest(),
    }
    fresh_record_payload = _canonical_pretty_json(fresh_record)
    fresh_record_sha256 = hashlib.sha256(fresh_record_payload).hexdigest()
    stored_fresh_record_sha256 = _write_raw(
        raw,
        RAW_FRESH_RECORD_NAME,
        fresh_record_payload,
        label="raw fresh download verification record",
    )
    _require(
        stored_fresh_record_sha256 == fresh_record_sha256,
        "fresh download verification record digest changed while publishing",
    )
    raw_sha256[RAW_FRESH_RECORD_NAME] = stored_fresh_record_sha256

    release_after_raw = _observe_remote_json(
        github_cli,
        release_arguments,
        raw_directory=raw,
        raw_name=RAW_RELEASE_AFTER_NAME,
        maximum_bytes=MAX_RELEASE_VIEW_BYTES,
        environment=github_environment,
        label="GitHub platform release view-after",
        runner=runner,
    )
    raw_sha256[RAW_RELEASE_AFTER_NAME] = hashlib.sha256(
        release_after_raw
    ).hexdigest()
    repository_after_raw = _observe_remote_json(
        github_cli,
        repository_arguments,
        raw_directory=raw,
        raw_name=RAW_REPOSITORY_AFTER_NAME,
        maximum_bytes=MAX_REPOSITORY_VIEW_BYTES,
        environment=github_environment,
        label="GitHub platform repository view-after",
        runner=runner,
    )
    raw_sha256[RAW_REPOSITORY_AFTER_NAME] = hashlib.sha256(
        repository_after_raw
    ).hexdigest()
    try:
        release_after = github_release.parse_release_view(
            release_after_raw,
            policy=policy,
            label="GitHub platform release view-after",
        )
        repository_after = github_release.parse_repository_view(
            repository_after_raw,
            policy=repository_policy,
            label="GitHub platform repository view-after",
        )
    except github_release.GitHubReleaseObservationError as exc:
        raise PlatformV010PublicationError(str(exc)) from exc
    _require(
        release_after.canonical == release_before.canonical,
        "GitHub platform release changed during verification",
    )
    _require(
        repository_after.canonical == repository_before.canonical,
        "GitHub repository visibility changed during platform verification",
    )
    source_after = source_inspector(
        verifier.path,
        git=GIT,
        environment=git_environment,
        runner=runner,
    )
    verify_transaction_handles()
    _require(
        source_after == source_before,
        "platform verifier checkout changed during collection",
    )
    _validate_raw_directory(raw, raw_sha256)
    observed_at = _utc_now(
        clock,
        label="platform verified observation",
        not_before=(
            _contract_timestamp(
                pending_observation["observed_at"], "pending platform observed_at"
            ),
            _contract_timestamp(fresh_verified_at, "fresh platform verified_at"),
        ),
    )
    verified_observation = dict(pending_observation)
    verified_observation["observed_at"] = observed_at
    verified_observation.update(
        {
            "android_runtime_evidence": runtime,
            "assets": list(release_before.assets),
            "checksums_sha256": assets[RELEASE_SUMS]["sha256"],
            "draft": False,
            "fresh_download_verification": {
                "asset_count": len(PUBLIC_ASSET_NAMES),
                "deep_distribution_verified": True,
                "record_sha256": fresh_record_sha256,
                "verified_at": fresh_verified_at,
                "verifier_commit": source_before.verifier_commit,
            },
            "immutable_release": True,
            "platform_distribution_sha256": assets[RELEASE_MANIFEST]["sha256"],
            "prerelease": False,
            "public_release": True,
            "published_at": release_before.published_at,
            "registries": dict(REGISTRY_STATES),
            "release_asset_verification_count": len(PUBLIC_ASSET_NAMES),
            "release_attestation": release_verification.projection(
                include_verified_at=False
            ),
            "release_id": release_before.release_id,
        }
    )
    verified_receipt = dict(receipt)
    verified_receipt["observation"] = verified_observation
    verified_receipt["status"] = PLATFORM_V0_1_0_STATUS_VERIFIED
    try:
        validate_v0_1_0_publication_receipt(verified_receipt)
    except PlatformV010PublicationContractError as exc:
        raise PlatformV010PublicationError(
            "platform publication receipt violates its domain contract: "
            f"{exc}"
        ) from exc
    return verified_receipt, release_before.release_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    pending = subparsers.add_parser("pending")
    pending.add_argument("--candidate-projection", required=True, type=pathlib.Path)
    pending.add_argument("--verifier-checkout", required=True, type=pathlib.Path)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--pending-receipt", required=True, type=pathlib.Path)
    collect.add_argument("--verifier-checkout", required=True, type=pathlib.Path)
    collect.add_argument("--raw-directory", required=True, type=pathlib.Path)
    collect.add_argument("--download-directory", required=True, type=pathlib.Path)
    collect.add_argument("--android-llvm-nm", required=True, type=pathlib.Path)
    collect.add_argument("--android-llvm-readelf", required=True, type=pathlib.Path)
    collect.add_argument("--android-apksigner", required=True, type=pathlib.Path)
    collect.add_argument("--android-zipalign", required=True, type=pathlib.Path)
    return parser


def _relative_output(path: pathlib.Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise PlatformV010PublicationError(
            "platform publication receipt output escaped the repository"
        ) from exc


def main(argv: Sequence[str]) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "pending":
            output, digest, source = assemble_pending_receipt(
                arguments.candidate_projection,
                arguments.verifier_checkout,
            )
            print(
                "ABI2_PLATFORM_V0_1_0_PENDING_RECEIPT_PASS "
                f"commit={source.tag_commit} receipt_sha256={digest} "
                f"receipt={_relative_output(output)}"
            )
        else:
            output, digest, release_id = collect_verified_receipt(
                arguments.pending_receipt,
                arguments.verifier_checkout,
                arguments.raw_directory,
                arguments.download_directory,
                android_tools=AndroidVerificationTools(
                    llvm_nm=arguments.android_llvm_nm,
                    llvm_readelf=arguments.android_llvm_readelf,
                    apksigner=arguments.android_apksigner,
                    zipalign=arguments.android_zipalign,
                ),
            )
            print(
                "ABI2_PLATFORM_V0_1_0_VERIFIED_RECEIPT_PASS "
                f"assets={len(PUBLIC_ASSET_NAMES)} release_id={release_id} "
                f"receipt_sha256={digest} "
                f"receipt={_relative_output(output)}"
            )
    except PublicationReceiptCommittedError as exc:
        if exc.leaf is not None and exc.digest is not None:
            print(
                "PUBLICATION_RECEIPT_COMMITTED_ERROR "
                f"visibility={exc.visibility} leaf={exc.leaf} "
                f"sha256={exc.digest}",
                file=sys.stderr,
            )
        else:
            print(
                "error: publication receipt committed with incomplete durability",
                file=sys.stderr,
            )
        return 125
    except PlatformV010PublicationRetryableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, PlatformV010PublicationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
