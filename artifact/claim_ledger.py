#!/usr/bin/env python3
"""Validate Q-Periapt's claim ledger and canonical source-input digest."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
from collections.abc import Iterable, Mapping

from evidence_io import EvidenceIOError, load_json_object_snapshot
from git_provenance import (
    GENERATED_EVIDENCE_PATHS,
    GitProvenanceError,
    repository_paths as secure_repository_paths,
)
from proof_manifest import ProofManifestError, load_results_manifest_snapshot


ALLOWED_STATUS = {"machine_checked", "implementation_tested", "diagnostic", "pending"}
MAX_CLAIM_LEDGER_BYTES = 2 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Generated evidence does not recursively participate in the canonical source-input
# digest. The historical camera transcript is bound by a named hash in
# artifact/results.json. A clean committed or signed release must bind that mutable
# manifest root; the exclusions-aware digest cannot recursively authenticate it.
EXCLUDED_FROM_TREE = set(GENERATED_EVIDENCE_PATHS)


class LedgerError(ValueError):
    """A fail-closed ledger or provenance validation error."""


def _inside(root: pathlib.Path, relative: str) -> pathlib.Path:
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise LedgerError(f"unsafe evidence path: {relative!r}")
    resolved = (root / pathlib.Path(*path.parts)).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise LedgerError(f"evidence path escapes repository: {relative!r}") from error
    return resolved


def validate_ledger(root: pathlib.Path, ledger: dict[str, object]) -> None:
    """Validate schema, unique claims, honest status, and evidence paths."""

    if ledger.get("schema_version") != 1:
        raise LedgerError("claim ledger schema_version must be 1")
    claims = ledger.get("claims")
    if not isinstance(claims, list) or not claims:
        raise LedgerError("claim ledger must contain a non-empty claims list")
    seen: set[str] = set()
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict):
            raise LedgerError(f"claim {index} must be an object")
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not claim_id or claim_id in seen:
            raise LedgerError(f"claim {index} has a missing or duplicate id")
        seen.add(claim_id)
        status = claim.get("status")
        if status not in ALLOWED_STATUS:
            raise LedgerError(f"claim {claim_id} has invalid status: {status!r}")
        for key in ("title", "boundary"):
            if not isinstance(claim.get(key), str) or not claim[key]:
                raise LedgerError(f"claim {claim_id} requires non-empty {key}")
        evidence = claim.get("evidence")
        if not isinstance(evidence, dict) or not evidence:
            raise LedgerError(f"claim {claim_id} requires evidence classes")
        evidence_count = 0
        for evidence_class, paths in evidence.items():
            if not isinstance(evidence_class, str) or not evidence_class:
                raise LedgerError(f"claim {claim_id} has an invalid evidence class")
            if not isinstance(paths, list):
                raise LedgerError(f"claim {claim_id}/{evidence_class} must be a list")
            for relative in paths:
                if not isinstance(relative, str):
                    raise LedgerError(f"claim {claim_id} has a non-string evidence path")
                path = _inside(root, relative)
                if not path.is_file():
                    raise LedgerError(f"claim {claim_id} evidence is missing: {relative}")
                evidence_count += 1
        if status != "pending" and evidence_count == 0:
            raise LedgerError(f"non-pending claim {claim_id} has no concrete evidence")


def canonical_tree_digest(
    root: pathlib.Path,
    relative_paths: Iterable[str],
    *,
    pinned_files: Mapping[str, bytes] | None = None,
) -> str:
    """Hash canonical source inputs in deterministic path order."""

    paths = sorted(set(relative_paths))
    pinned = dict(pinned_files or {})
    unused = set(pinned) - set(paths)
    if unused:
        raise LedgerError(f"pinned source inputs are absent from inventory: {sorted(unused)}")
    inputs: dict[str, bytes] = {}
    for relative in paths:
        if relative not in EXCLUDED_FROM_TREE:
            path = _inside(root, relative)
            if not path.is_file():
                raise LedgerError(f"source-input path is missing: {relative}")
            content = pinned.get(relative)
            inputs[relative] = content if content is not None else path.read_bytes()
    return canonical_file_map_digest(inputs)


def canonical_file_map_digest(files: Mapping[str, bytes]) -> str:
    """Hash an already-materialized canonical source-input file map."""

    digest = hashlib.sha256()
    for relative in sorted(files):
        if relative in EXCLUDED_FROM_TREE:
            continue
        path = pathlib.PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise LedgerError(f"unsafe source-input path: {relative!r}")
        content = files[relative]
        if not isinstance(content, bytes):
            raise LedgerError(f"source-input content must be bytes: {relative}")
        path_bytes = relative.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def repository_paths(root: pathlib.Path) -> list[str]:
    """Return tracked plus visible/ignored untracked canonical source candidates."""

    try:
        return secure_repository_paths(root)
    except GitProvenanceError as exc:
        raise LedgerError(str(exc)) from exc


def verify(
    root: pathlib.Path,
    ledger_path: pathlib.Path,
    manifest_path: pathlib.Path,
    expected_manifest_sha256: str | None = None,
) -> str:
    try:
        ledger_snapshot = load_json_object_snapshot(
            ledger_path,
            maximum=MAX_CLAIM_LEDGER_BYTES,
            label="claim ledger",
        )
        manifest_snapshot = load_results_manifest_snapshot(
            manifest_path,
            expected_sha256=expected_manifest_sha256,
        )
    except (EvidenceIOError, ProofManifestError) as exc:
        raise LedgerError(str(exc)) from exc
    ledger = ledger_snapshot.value
    manifest = manifest_snapshot.value
    validate_ledger(root, ledger)
    # The manifest key and legacy PASS marker retain their historical names for
    # schema compatibility. Their defined value is the exclusions-aware canonical
    # source-input digest above, not a raw Git tree hash or hermetic build closure.
    expected = manifest.get("proof_source_tree_sha256")
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise LedgerError("artifact/results.json lacks proof_source_tree_sha256")
    try:
        ledger_relative = ledger_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise LedgerError("claim ledger must be under the repository root") from exc
    actual = canonical_tree_digest(
        root,
        repository_paths(root),
        pinned_files={ledger_relative: ledger_snapshot.file.data},
    )
    if actual != expected:
        raise LedgerError(
            f"canonical source-input digest mismatch: got {actual}, expected {expected}"
        )
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--ledger", type=pathlib.Path, required=True)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--expected-manifest-sha256", default=None)
    args = parser.parse_args()
    root = args.root.resolve()
    actual = verify(
        root,
        args.ledger.resolve(),
        args.manifest.resolve(),
        args.expected_manifest_sha256,
    )
    print(f"CLAIM_LEDGER_AND_SOURCE_TREE_PASS sha256={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
