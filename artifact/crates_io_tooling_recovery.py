#!/usr/bin/env python3
"""Bind a crates.io tooling correction to the frozen 0.1.5 publication.

The existing coordinator still owns handoff loading, uploader installation,
journals, locking, credentials, and registry observations. This module validates
only the explicit S/R/P/V/W Git lineage used by its source-transition verifier.
It does not make W a product source or a parent for final results commit Q.
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import re
from typing import Never

from apple_verifier_recovery import APPLE_VERIFIER_RECOVERY_ALLOWED_PATHS
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
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULTS_PATH = "artifact/results.json"

# This list applies only AFTER the reviewed Apple verifier V. In particular,
# registry metadata derivation, the uploader builder, handoff readers, package
# contracts, dependencies, workflows, and results are not recovery inputs.
CRATES_IO_TOOLING_RECOVERY_ALLOWED_PATHS = frozenset(
    {
        "artifact/crates_io_publication.py",
        "artifact/crates_io_tooling_recovery.py",
        "artifact/crates_io_upload_diagnostic.py",
        "artifact/crates_io_uploader_template.py.in",
        "artifact/test_crates_io_publication.py",
        "artifact/test_crates_io_tooling_recovery.py",
        "artifact/test_crates_io_upload_diagnostic.py",
        "artifact/test_crates_io_uploader_diagnostics.py",
        "artifact/stable-release-notes.md",
        "ARTIFACT.md",
        "README.md",
        "docs/EMBEDDING_READINESS.md",
    }
)


class CratesIoToolingRecoveryError(ValueError):
    """The requested tooling checkout differs from the frozen release lineage."""


@dataclasses.dataclass(frozen=True, slots=True)
class CratesIoToolingRecoveryLineage:
    source_commit: str
    tag_commit: str
    pending_commit: str
    base_verifier_commit: str
    tooling_commit: str
    pending_results_sha256: str
    changed_paths: tuple[str, ...]


def _fail(message: str) -> Never:
    raise CratesIoToolingRecoveryError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _require_identity(value: object, pattern: re.Pattern[str], label: str) -> None:
    _require(
        isinstance(value, str) and pattern.fullmatch(value) is not None,
        f"{label} is malformed",
    )


def _results_bytes(root: pathlib.Path, commit: str) -> bytes:
    name = f"{commit}:{RESULTS_PATH}"
    _require(run_git_text(root, ["cat-file", "-t", name]) == "blob",
             "recovery results is not a Git blob")
    size = run_git_text(root, ["cat-file", "-s", name])
    _require(re.fullmatch(r"[1-9][0-9]*", size) is not None,
             "recovery results Git size is malformed")
    _require(int(size) <= MAX_RESULTS_BYTES, "recovery results exceeds its bound")
    payload = run_git_bytes(root, ["cat-file", "blob", name])
    _require(len(payload) == int(size), "recovery results Git size changed")
    return payload


def _pending_source_identity(payload: bytes) -> StableSourceIdentity:
    value = parse_strict_json_bytes(payload, label="crates.io recovery pending results")
    _require(isinstance(value, dict) and all(isinstance(key, str) for key in value),
             "recovery pending results must be a JSON object")
    _require(publication_state(value) == PUBLICATION_STATE_PENDING,
             "recovery base is not the coordinated pending publication")
    identity = stable_source_identity(value)
    _require(identity is not None, "recovery pending results lacks a source identity")
    return identity


def _linear_changed_paths(
    root: pathlib.Path,
    start: str,
    end: str,
    *,
    allowed_paths: frozenset[str],
    label: str,
) -> tuple[str, ...]:
    """Check every edge, including changes subsequently reverted or renamed."""

    _require(start != end, f"{label} requires a distinct successor")
    require_commit_ancestor(root, start, end)
    revisions = run_git_text(
        root, ["rev-list", "--reverse", "--topo-order", f"{start}..{end}"]
    ).splitlines()
    _require(bool(revisions), f"{label} commit range is empty")
    previous = start
    changed: set[str] = set()
    for revision in revisions:
        parents = run_git_text(root, ["rev-list", "--parents", "-n", "1", revision])
        _require(parents.split() == [revision, previous],
                 f"{label} must be one linear no-merge chain")
        raw_paths = run_git_bytes(
            root, ["diff", "--no-renames", "--name-only", "-z", previous, revision, "--"]
        )
        try:
            paths = tuple(path.decode("utf-8") for path in raw_paths.split(b"\0") if path)
        except UnicodeDecodeError as exc:
            raise CratesIoToolingRecoveryError(f"{label} paths are not UTF-8") from exc
        _require(bool(paths), f"{label} contains an empty commit")
        _require(RESULTS_PATH not in paths, f"{label} must not change release results")
        unexpected = set(paths) - allowed_paths
        _require(not unexpected,
                 f"{label} changed forbidden paths: " + ", ".join(sorted(unexpected)[:8]))
        changed.update(paths)
        previous = revision
    _require(previous == end, f"{label} does not end at the pinned commit")
    return tuple(sorted(changed))


def validate_crates_io_tooling_recovery_lineage(
    repository_root: pathlib.Path,
    *,
    source_commit: str,
    tag_commit: str,
    tag_tree: str,
    canonical_source_tree_sha256: str,
    pending_commit: str,
    expected_pending_results_sha256: str,
    base_verifier_commit: str,
    expected_tooling_commit: str,
) -> CratesIoToolingRecoveryLineage:
    """Validate an explicitly selected recovery without changing source policy.

    Callers must also run the coordinator's existing R-selected handoff check.
    Its normal snapshot/resample path continues to bind all archive, transcript,
    package, and metadata inputs. No failed normal check selects this function.
    """

    for value, label in (
        (source_commit, "source S"),
        (tag_commit, "tag R"),
        (tag_tree, "tag tree"),
        (pending_commit, "pending P"),
        (base_verifier_commit, "base verifier V"),
        (expected_tooling_commit, "tooling W"),
    ):
        _require_identity(value, COMMIT_RE, label)
    _require_identity(canonical_source_tree_sha256, SHA256_RE, "canonical source digest")
    _require_identity(expected_pending_results_sha256, SHA256_RE, "pending results digest")

    try:
        inspection = inspect_worktree(repository_root)
        _require(not inspection.dirty, "tooling recovery requires a clean checkout")
        _require(inspection.commit == expected_tooling_commit,
                 "tooling checkout differs from the explicit commit W")
        require_direct_results_only_child(repository_root, source_commit, tag_commit)
        require_direct_results_only_child(repository_root, tag_commit, pending_commit)
        pending_bytes = _results_bytes(repository_root, pending_commit)
        _require(hashlib.sha256(pending_bytes).hexdigest() == expected_pending_results_sha256,
                 "pending results differs from its explicit digest")
        source = _pending_source_identity(pending_bytes)
        _require(
            source == StableSourceIdentity(
                source_parent_commit=source_commit,
                tag_commit=tag_commit,
                tag_tree=tag_tree,
                canonical_source_tree_sha256=canonical_source_tree_sha256,
            ),
            "pending results source identity differs from explicit S/R pins",
        )
        _require(run_git_text(repository_root, ["rev-parse", "--verify", f"{tag_commit}^{{tree}}"])
                 == tag_tree, "recovery tag tree differs from Git")
        apple_paths = _linear_changed_paths(
            repository_root, pending_commit, base_verifier_commit,
            allowed_paths=APPLE_VERIFIER_RECOVERY_ALLOWED_PATHS,
            label="P-to-V verifier history",
        )
        registry_paths = _linear_changed_paths(
            repository_root, base_verifier_commit, expected_tooling_commit,
            allowed_paths=CRATES_IO_TOOLING_RECOVERY_ALLOWED_PATHS,
            label="V-to-W registry history",
        )
        _require(_results_bytes(repository_root, expected_tooling_commit) == pending_bytes,
                 "tooling recovery must retain byte-identical pending results")
        _require(inspect_worktree(repository_root) == inspection,
                 "tooling checkout changed during recovery validation")
    except (GitProvenanceError, EvidenceIOError, ReleasePublicationContractError) as exc:
        raise CratesIoToolingRecoveryError("cannot validate crates.io tooling recovery lineage") from exc
    return CratesIoToolingRecoveryLineage(
        source_commit=source_commit,
        tag_commit=tag_commit,
        pending_commit=pending_commit,
        base_verifier_commit=base_verifier_commit,
        tooling_commit=expected_tooling_commit,
        pending_results_sha256=expected_pending_results_sha256,
        changed_paths=tuple(sorted(set(apple_paths) | set(registry_paths))),
    )
