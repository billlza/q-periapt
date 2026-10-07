#!/usr/bin/env python3
"""Validate a narrow post-publication Apple verifier recovery lineage.

This module deliberately does not broaden the repository-wide generated-evidence
policy.  It validates one separate verifier checkout whose release artifacts and
pending results remain frozen at the already-installed 0.1.5 publication state.
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import re
from typing import Never

from evidence_io import EvidenceIOError, parse_strict_json_bytes
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_commit_ancestor,
    require_direct_results_only_child,
    run_git_bytes,
    run_git_text,
)
from release_publication_contract import (
    PUBLICATION_STATE_PENDING,
    ReleasePublicationContractError,
    StableSourceIdentity,
    publication_state,
    stable_source_identity,
)


MAX_RESULTS_BYTES = 16 * 1024 * 1024
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULTS_PATH = "artifact/results.json"

# This is an intentionally release-specific recovery surface.  Product code,
# package manifests, dependencies, workflows, and release results are absent.
APPLE_VERIFIER_RECOVERY_RUNTIME_PATHS = frozenset(
    {
        "artifact/apple_stable_publication.py",
        "artifact/apple_verifier_recovery.py",
        "artifact/github_release_observation.py",
        "artifact/git_provenance.py",
        "artifact/platform_publication_contract.py",
        "artifact/release_publication_contract.py",
        "artifact/swift-xcframework-remote-consumer.sh",
    }
)
APPLE_VERIFIER_RECOVERY_TEST_PATHS = frozenset(
    {
        "artifact/test_apple_distribution.py",
        "artifact/test_apple_stable_publication.py",
        "artifact/test_apple_verifier_recovery.py",
        "artifact/test_github_release_observation.py",
        "artifact/test_git_provenance.py",
        "artifact/test_platform_publication_contract.py",
        "artifact/test_release_publication_contract.py",
    }
)
APPLE_VERIFIER_RECOVERY_DOCUMENTATION_PATHS = frozenset(
    {
        "README.md",
        "artifact/stable-release-notes.md",
        "docs/EMBEDDING_READINESS.md",
    }
)
APPLE_VERIFIER_RECOVERY_ALLOWED_PATHS = frozenset(
    APPLE_VERIFIER_RECOVERY_RUNTIME_PATHS
    | APPLE_VERIFIER_RECOVERY_TEST_PATHS
    | APPLE_VERIFIER_RECOVERY_DOCUMENTATION_PATHS
)


class AppleVerifierRecoveryError(ValueError):
    """The verifier checkout is not a narrow successor of frozen release P."""


@dataclasses.dataclass(frozen=True, slots=True)
class AppleVerifierRecoveryLineage:
    """Exact identities admitted for one read-only Apple verifier recovery."""

    source_commit: str
    tag_commit: str
    pending_commit: str
    verifier_commit: str
    pending_results_sha256: str
    changed_paths: tuple[str, ...]


def _fail(message: str) -> Never:
    raise AppleVerifierRecoveryError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _commit(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and COMMIT_RE.fullmatch(value) is not None,
        f"{label} is malformed",
    )
    return value


def _sha256(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{label} is malformed",
    )
    return value


def _decode_paths(raw: bytes, label: str) -> tuple[str, ...]:
    try:
        paths = tuple(part.decode("utf-8") for part in raw.split(b"\0") if part)
    except UnicodeDecodeError as exc:
        raise AppleVerifierRecoveryError(f"{label} is not UTF-8") from exc
    for path in paths:
        pure = pathlib.PurePosixPath(path)
        _require(
            bool(pure.parts)
            and not pure.is_absolute()
            and ".." not in pure.parts
            and pure.as_posix() == path,
            f"{label} contains a noncanonical path",
        )
    _require(len(paths) == len(set(paths)), f"{label} contains duplicate paths")
    return paths


def _git_results_bytes(repository_root: pathlib.Path, commit: str) -> bytes:
    object_name = f"{commit}:{RESULTS_PATH}"
    try:
        object_type = run_git_text(
            repository_root,
            ["cat-file", "-t", object_name],
        )
        size_text = run_git_text(
            repository_root,
            ["cat-file", "-s", object_name],
        )
        _require(object_type == "blob", "pending results is not one Git blob")
        _require(
            re.fullmatch(r"(?:0|[1-9][0-9]*)", size_text) is not None,
            "pending results Git size is malformed",
        )
        declared_size = int(size_text, 10)
        _require(
            0 < declared_size <= MAX_RESULTS_BYTES,
            "pending results Git size is outside the supported bound",
        )
        data = run_git_bytes(repository_root, ["cat-file", "blob", object_name])
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "cannot read the exact pending results Git blob"
        ) from exc
    _require(
        len(data) == declared_size,
        "pending results Git blob size changed while reading",
    )
    return data


def _pending_source_identity(results_bytes: bytes) -> StableSourceIdentity:
    try:
        value = parse_strict_json_bytes(
            results_bytes,
            label="Apple verifier recovery pending results",
        )
    except EvidenceIOError as exc:
        raise AppleVerifierRecoveryError(
            "pending results is not strict JSON"
        ) from exc
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        "pending results must be a JSON object with string keys",
    )
    try:
        _require(
            publication_state(value) == PUBLICATION_STATE_PENDING,
            "recovery base is not the coordinated pending publication",
        )
        identity = stable_source_identity(value)
    except ReleasePublicationContractError as exc:
        raise AppleVerifierRecoveryError(
            "pending results publication contract is invalid"
        ) from exc
    _require(identity is not None, "pending results lacks a stable source identity")
    return identity


def _validate_linear_verifier_delta(
    repository_root: pathlib.Path,
    *,
    pending_commit: str,
    verifier_commit: str,
) -> tuple[str, ...]:
    _require(
        pending_commit != verifier_commit,
        "verifier recovery requires a distinct verifier commit",
    )
    try:
        require_commit_ancestor(repository_root, pending_commit, verifier_commit)
        revision_text = run_git_text(
            repository_root,
            [
                "rev-list",
                "--reverse",
                "--topo-order",
                f"{pending_commit}..{verifier_commit}",
            ],
        )
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "verifier commit is not based on the explicit pending commit"
        ) from exc
    revisions = tuple(line for line in revision_text.splitlines() if line)
    _require(bool(revisions), "verifier recovery commit range is empty")

    previous = pending_commit
    changed_paths: set[str] = set()
    for revision in revisions:
        try:
            parent_fields = run_git_text(
                repository_root,
                ["rev-list", "--parents", "-n", "1", revision],
            ).split()
            _require(
                parent_fields == [revision, previous],
                "verifier recovery history is not one linear no-merge chain",
            )
            commit_paths = _decode_paths(
                run_git_bytes(
                    repository_root,
                    [
                        "diff",
                        "--no-renames",
                        "--name-only",
                        "-z",
                        previous,
                        revision,
                        "--",
                    ],
                ),
                "verifier recovery commit path inventory",
            )
        except GitProvenanceError as exc:
            raise AppleVerifierRecoveryError(
                "cannot inspect the verifier recovery commit range"
            ) from exc
        _require(bool(commit_paths), "verifier recovery contains an empty commit")
        _require(
            RESULTS_PATH not in commit_paths,
            "verifier recovery must not change release results",
        )
        unexpected = sorted(
            set(commit_paths) - APPLE_VERIFIER_RECOVERY_ALLOWED_PATHS
        )
        _require(
            not unexpected,
            "verifier recovery changed forbidden paths: "
            + ", ".join(unexpected[:8]),
        )
        changed_paths.update(commit_paths)
        previous = revision

    _require(
        previous == verifier_commit,
        "verifier recovery history does not end at the expected verifier commit",
    )
    return tuple(sorted(changed_paths))


def validate_apple_verifier_recovery_lineage(
    repository_root: pathlib.Path,
    *,
    source_commit: str,
    tag_commit: str,
    pending_commit: str,
    expected_pending_results_sha256: str,
    expected_verifier_commit: str,
) -> AppleVerifierRecoveryLineage:
    """Validate exact S -> R -> P and a narrow, separate P -> V lineage.

    ``P`` stays the authority for the pending release facts and results bytes.
    ``V`` identifies only the code that re-verifies the already-immutable public
    assets.  The function accepts no inferred base commit and no arbitrary source
    descendant.
    """

    source_commit = _commit(source_commit, "artifact source commit")
    tag_commit = _commit(tag_commit, "release tag commit")
    pending_commit = _commit(pending_commit, "pending results commit")
    expected_verifier_commit = _commit(
        expected_verifier_commit,
        "expected verifier commit",
    )
    expected_pending_results_sha256 = _sha256(
        expected_pending_results_sha256,
        "expected pending results SHA-256",
    )

    try:
        inspection = inspect_worktree(repository_root)
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "cannot inspect the verifier recovery checkout"
        ) from exc
    _require(
        not inspection.dirty,
        "verifier recovery requires a clean checkout",
    )
    _require(
        inspection.commit == expected_verifier_commit,
        "verifier checkout differs from the explicit verifier commit",
    )
    try:
        require_direct_results_only_child(
            repository_root,
            source_commit,
            tag_commit,
        )
        require_direct_results_only_child(
            repository_root,
            tag_commit,
            pending_commit,
        )
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "release recovery base is not exact S-to-R-to-P results-only history"
        ) from exc

    pending_results = _git_results_bytes(repository_root, pending_commit)
    _require(
        hashlib.sha256(pending_results).hexdigest()
        == expected_pending_results_sha256,
        "pending results differ from the explicit SHA-256",
    )
    identity = _pending_source_identity(pending_results)
    _require(
        identity.source_parent_commit == source_commit
        and identity.tag_commit == tag_commit,
        "pending publication identity differs from explicit S/R",
    )
    try:
        observed_tag_tree = run_git_text(
            repository_root,
            ["rev-parse", "--verify", f"{tag_commit}^{{tree}}"],
        )
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "cannot resolve the release tag commit tree"
        ) from exc
    _require(
        observed_tag_tree == identity.tag_tree,
        "pending publication tag tree differs from Git",
    )

    verifier_results = _git_results_bytes(repository_root, expected_verifier_commit)
    _require(
        verifier_results == pending_results,
        "verifier recovery must retain byte-identical pending results",
    )
    changed_paths = _validate_linear_verifier_delta(
        repository_root,
        pending_commit=pending_commit,
        verifier_commit=expected_verifier_commit,
    )
    try:
        final_inspection = inspect_worktree(repository_root)
    except GitProvenanceError as exc:
        raise AppleVerifierRecoveryError(
            "cannot recheck the verifier recovery checkout"
        ) from exc
    _require(
        final_inspection == inspection,
        "verifier recovery checkout changed during lineage validation",
    )
    return AppleVerifierRecoveryLineage(
        source_commit=source_commit,
        tag_commit=tag_commit,
        pending_commit=pending_commit,
        verifier_commit=expected_verifier_commit,
        pending_results_sha256=expected_pending_results_sha256,
        changed_paths=changed_paths,
    )
