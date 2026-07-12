#!/usr/bin/env python3
"""Freeze and finalize proof-to-byte release provenance."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Sequence

from claim_ledger import LedgerError, verify as verify_claim_ledger
from git_provenance import (
    GitProvenanceError,
    git_commit,
    inspect_worktree,
)


COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_NAMES = (
    "host_smoke",
    "formal",
    "apple_device",
    "apple_matrix",
    "android_runtime",
    "performance",
    "camera_ready",
    "camera_required",
    "dependency_audit",
    "source_tree_dirty",
    "allow_dirty_apple",
    "allow_dirty_performance",
)


class FinalizerError(ValueError):
    """The release state or source snapshot cannot support attestation."""


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    commit: str
    source_sha256: str
    manifest_sha256: str
    dirty: bool


@dataclass(frozen=True, slots=True)
class AttestationState:
    host_smoke: bool
    formal: bool
    apple_device: bool
    apple_matrix: bool
    android_runtime: bool
    performance: bool
    camera_ready: bool
    camera_required: bool
    dependency_audit: bool
    source_tree_dirty: bool
    allow_dirty_apple: bool
    allow_dirty_performance: bool

    @classmethod
    def from_values(cls, values: Sequence[str]) -> "AttestationState":
        if len(values) != len(STATE_NAMES):
            raise FinalizerError(
                f"release attestation requires exactly {len(STATE_NAMES)} state values"
            )
        parsed: list[bool] = []
        for name, value in zip(STATE_NAMES, values, strict=True):
            if value not in {"0", "1"}:
                raise FinalizerError(
                    f"release attestation state must be 0 or 1: {name}={value}"
                )
            parsed.append(value == "1")
        return cls(*parsed)


def _require_commit(value: str, label: str) -> None:
    if COMMIT_RE.fullmatch(value) is None:
        raise FinalizerError(f"{label} is not a canonical Git commit id")


def _require_sha256(value: str, label: str) -> None:
    if SHA256_RE.fullmatch(value) is None:
        raise FinalizerError(f"{label} is not a SHA-256 digest")


def capture_source_snapshot(
    root: pathlib.Path,
    ledger: pathlib.Path,
    manifest: pathlib.Path,
    expected_manifest_sha256: str,
    *,
    expected_commit: str | None = None,
    expected_source_sha256: str | None = None,
    expected_dirty: bool | None = None,
) -> SourceSnapshot:
    """Double-sample the manifest, canonical source, HEAD, and dirty state."""

    _require_sha256(expected_manifest_sha256, "expected manifest digest")
    if expected_commit is not None:
        _require_commit(expected_commit, "expected Git commit")
    if expected_source_sha256 is not None:
        _require_sha256(expected_source_sha256, "expected source digest")

    try:
        commit_before = git_commit(root)
        if expected_commit is not None and commit_before != expected_commit:
            raise FinalizerError(
                "Git commit changed during proof-to-byte run: "
                f"got {commit_before}, expected {expected_commit}"
            )
        digest_before = verify_claim_ledger(
            root,
            ledger,
            manifest,
            expected_manifest_sha256,
        )
        inspection = inspect_worktree(root)
        digest_after = verify_claim_ledger(
            root,
            ledger,
            manifest,
            expected_manifest_sha256,
        )
        commit_after = git_commit(root)
    except (GitProvenanceError, LedgerError, OSError) as exc:
        raise FinalizerError(str(exc)) from exc

    if not (commit_before == inspection.commit == commit_after):
        raise FinalizerError(
            "Git commit changed while finalizing proof-to-byte provenance: "
            f"before={commit_before} inspected={inspection.commit} after={commit_after}"
        )
    if digest_before != digest_after:
        raise FinalizerError(
            "canonical source digest changed while finalizing proof-to-byte provenance: "
            f"before={digest_before} after={digest_after}"
        )
    if expected_source_sha256 is not None and digest_after != expected_source_sha256:
        raise FinalizerError(
            "canonical source digest changed during proof-to-byte run: "
            f"got {digest_after}, expected {expected_source_sha256}"
        )
    if expected_dirty is not None and inspection.dirty is not expected_dirty:
        raise FinalizerError(
            "source dirty state changed during proof-to-byte run: "
            f"got {int(inspection.dirty)}, expected {int(expected_dirty)}"
        )

    return SourceSnapshot(
        commit=commit_after,
        source_sha256=digest_after,
        manifest_sha256=expected_manifest_sha256,
        dirty=inspection.dirty,
    )


def format_attestation_marker(
    state: AttestationState,
    snapshot: SourceSnapshot,
) -> str:
    """Return the scoped release summary bound to the verified source snapshot."""

    _require_commit(snapshot.commit, "attested Git commit")
    _require_sha256(snapshot.source_sha256, "attested source digest")
    _require_sha256(snapshot.manifest_sha256, "attested manifest digest")
    provenance = (
        f" commit={snapshot.commit}"
        f" source_sha256={snapshot.source_sha256}"
        f" manifest_sha256={snapshot.manifest_sha256}"
    )
    complete = (
        state.host_smoke
        and state.formal
        and state.apple_matrix
        and state.performance
        and (not state.camera_required or state.camera_ready)
        and state.dependency_audit
    )
    if complete:
        if state.source_tree_dirty:
            return "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED reason=dirty_source_tree" + provenance
        if state.allow_dirty_apple or state.allow_dirty_performance:
            return (
                "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED "
                "reason=diagnostic_proof_override" + provenance
            )
        camera = "verified" if state.camera_required else "not_required"
        return (
            "PROOF_TO_BYTE_APPLE_RELEASE_PASS "
            f"camera_ready_bundle={camera}" + provenance
        )
    return (
        "PROOF_TO_BYTE_RUN_FINISHED"
        f" host_smoke={int(state.host_smoke)}"
        f" formal={int(state.formal)}"
        f" apple_device={int(state.apple_device)}"
        f" apple_matrix={int(state.apple_matrix)}"
        f" android_runtime={int(state.android_runtime)}"
        f" performance={int(state.performance)}"
        f" camera_ready_bundle={int(state.camera_ready)}"
        f" camera_ready_required={int(state.camera_required)}"
        f" dependency_audit={int(state.dependency_audit)}"
        f" allow_dirty_apple_proof={int(state.allow_dirty_apple)}"
        f" allow_dirty_performance_proof={int(state.allow_dirty_performance)}"
        + provenance
    )


def _production_state(values: Sequence[str], dirty: bool) -> AttestationState:
    if len(values) != len(STATE_NAMES) - 1:
        raise FinalizerError("finalize requires exactly 11 gate state values")
    with_dirty = [*values[:9], str(int(dirty)), *values[9:]]
    return AttestationState.from_values(with_dirty)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--root", type=pathlib.Path, required=True)
    freeze.add_argument("--ledger", type=pathlib.Path, required=True)
    freeze.add_argument("--manifest", type=pathlib.Path, required=True)
    freeze.add_argument("--expected-manifest-sha256", required=True)

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--root", type=pathlib.Path, required=True)
    finalize.add_argument("--ledger", type=pathlib.Path, required=True)
    finalize.add_argument("--manifest", type=pathlib.Path, required=True)
    finalize.add_argument("--expected-manifest-sha256", required=True)
    finalize.add_argument("--expected-git-commit", required=True)
    finalize.add_argument("--expected-source-sha256", required=True)
    finalize.add_argument("--expected-source-dirty", choices=("0", "1"), required=True)
    finalize.add_argument("states", nargs="*")

    return parser


def run(args: argparse.Namespace) -> None:
    if args.command == "freeze":
        snapshot = capture_source_snapshot(
            args.root.resolve(),
            args.ledger.resolve(),
            args.manifest.resolve(),
            args.expected_manifest_sha256,
        )
        print(
            f"{snapshot.commit}:{snapshot.source_sha256}:{int(snapshot.dirty)}"
        )
        return
    expected_dirty = args.expected_source_dirty == "1"
    snapshot = capture_source_snapshot(
        args.root.resolve(),
        args.ledger.resolve(),
        args.manifest.resolve(),
        args.expected_manifest_sha256,
        expected_commit=args.expected_git_commit,
        expected_source_sha256=args.expected_source_sha256,
        expected_dirty=expected_dirty,
    )
    state = _production_state(args.states, snapshot.dirty)
    print("PROOF_TO_BYTE_RESULTS_MANIFEST_STABLE_PASS")
    print(
        "PROOF_TO_BYTE_FINAL_SOURCE_SNAPSHOT_PASS"
        f" commit={snapshot.commit}"
        f" source_sha256={snapshot.source_sha256}"
        f" manifest_sha256={snapshot.manifest_sha256}"
    )
    print(format_attestation_marker(state, snapshot))


def main() -> int:
    try:
        run(build_parser().parse_args())
    except FinalizerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
