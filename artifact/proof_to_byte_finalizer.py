#!/usr/bin/env python3
"""Freeze and finalize proof-to-byte release provenance."""

from __future__ import annotations

import argparse
import csv
import io
import math
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Sequence

from claim_ledger import LedgerError, verify as verify_claim_ledger
from evidence_io import EvidenceIOError, read_regular_snapshot
from git_provenance import (
    GitProvenanceError,
    git_commit,
    inspect_worktree,
    require_commit_or_evidence_successor,
)
from proof_manifest import ProofManifestError, load_results_manifest_snapshot


COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INTEGER_RE = re.compile(r"^[1-9][0-9]*$")
KIB_RE = re.compile(r"^(?:0|[1-9][0-9]*)\.[0-9]$")
MAX_FOOTPRINT_CSV_BYTES = 64 * 1024
MAX_FOOTPRINT_ARTIFACT_BYTES = (1 << 63) - 1
FOOTPRINT_NOTE = "Platform-dependent; regenerate per host with `sh paper/footprint.sh`."
FOOTPRINT_ARTIFACTS = {
    "c-abi-cdylib-stripped": "c_abi_cdylib_stripped",
    "wasm-lean-default": "wasm_lean_default",
    "wasm-signed-policy": "wasm_signed_policy",
}
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


def _footprint_field_error(artifact: str, field: str, detail: str) -> FinalizerError:
    return FinalizerError(
        f"footprint CSV artifact {artifact!r} field {field!r} {detail}"
    )


def _parse_footprint_byte_count(raw: str, artifact: str) -> int:
    """Parse one bounded canonical byte count without native integer-limit errors."""

    if POSITIVE_INTEGER_RE.fullmatch(raw) is None:
        raise _footprint_field_error(artifact, "bytes", f"is not canonical: {raw!r}")
    maximum = str(MAX_FOOTPRINT_ARTIFACT_BYTES)
    if len(raw) > len(maximum) or (len(raw) == len(maximum) and raw > maximum):
        raise _footprint_field_error(
            artifact,
            "bytes",
            f"exceeds the supported maximum {MAX_FOOTPRINT_ARTIFACT_BYTES}",
        )
    try:
        return int(raw, 10)
    except (ValueError, OverflowError) as exc:
        raise _footprint_field_error(
            artifact,
            "bytes",
            "cannot be represented as a bounded integer",
        ) from exc


def _format_kib(byte_count: int) -> str:
    """Format bytes as one-decimal KiB using exact round-to-nearest-even."""

    tenths, remainder = divmod(byte_count * 10, 1024)
    if remainder > 512 or (remainder == 512 and tenths % 2 == 1):
        tenths += 1
    return f"{tenths // 10}.{tenths % 10}"


def _load_footprint_csv(path: pathlib.Path) -> tuple[dict[str, object], str]:
    """Strict-load the canonical footprint CSV and derive its manifest value."""

    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=MAX_FOOTPRINT_CSV_BYTES,
            label="footprint CSV",
        )
        text = snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise FinalizerError(f"cannot read strict UTF-8 footprint CSV: {exc}") from exc

    data_lines = [line for line in text.splitlines() if not line.startswith("#")]
    if not data_lines or any(not line for line in data_lines):
        raise FinalizerError("footprint CSV must contain a header and three non-empty rows")
    try:
        reader = csv.DictReader(io.StringIO("\n".join(data_lines) + "\n"), strict=True)
        expected_columns = ["host", "rustc", "artifact", "bytes", "kib"]
        if reader.fieldnames != expected_columns:
            raise FinalizerError(
                f"footprint CSV columns differ: {reader.fieldnames} != {expected_columns}"
            )
        rows = list(reader)
    except csv.Error as exc:
        raise FinalizerError(f"cannot parse footprint CSV: {exc}") from exc
    if len(rows) != len(FOOTPRINT_ARTIFACTS):
        raise FinalizerError(
            f"footprint CSV must contain exactly {len(FOOTPRINT_ARTIFACTS)} rows"
        )

    values: dict[str, object] = {}
    hosts: set[str] = set()
    rustcs: set[str] = set()
    seen: set[str] = set()
    for row in rows:
        if None in row or any(value is None for value in row.values()):
            raise FinalizerError("footprint CSV row has a missing or extra field")
        host = row["host"]
        rustc = row["rustc"]
        artifact = row["artifact"]
        raw_bytes = row["bytes"]
        raw_kib = row["kib"]
        if not host or not rustc:
            raise FinalizerError("footprint CSV host and rustc must be non-empty")
        if artifact not in FOOTPRINT_ARTIFACTS or artifact in seen:
            raise FinalizerError(
                f"footprint CSV has an unknown or duplicate artifact: {artifact!r}"
            )
        if KIB_RE.fullmatch(raw_kib) is None:
            raise _footprint_field_error(
                artifact,
                "kib",
                f"is not canonical: {raw_kib!r}",
            )
        byte_count = _parse_footprint_byte_count(raw_bytes, artifact)
        expected_kib = _format_kib(byte_count)
        if raw_kib != expected_kib:
            raise _footprint_field_error(
                artifact,
                "kib",
                f"differs from bytes: {raw_kib} != {expected_kib}",
            )
        try:
            kib_value = float(expected_kib)
        except (ValueError, OverflowError) as exc:
            raise _footprint_field_error(
                artifact,
                "kib",
                "cannot be represented as a finite manifest number",
            ) from exc
        if not math.isfinite(kib_value):
            raise _footprint_field_error(
                artifact,
                "kib",
                "cannot be represented as a finite manifest number",
            )
        seen.add(artifact)
        hosts.add(host)
        rustcs.add(rustc)
        values[FOOTPRINT_ARTIFACTS[artifact]] = {
            "bytes": byte_count,
            "kib": kib_value,
        }
    if seen != set(FOOTPRINT_ARTIFACTS):
        raise FinalizerError("footprint CSV artifact set is incomplete")
    if len(hosts) != 1 or len(rustcs) != 1:
        raise FinalizerError("footprint CSV rows must share one host and rustc version")
    values["note"] = FOOTPRINT_NOTE
    values["platform"] = f"{hosts.pop()}, rustc {rustcs.pop()}"
    return values, snapshot.sha256


def validate_release_metadata(
    root: pathlib.Path,
    manifest: pathlib.Path,
    expected_manifest_sha256: str,
) -> tuple[str, str]:
    """Bind the manifest to its source commit and canonical footprint CSV."""

    try:
        document = load_results_manifest_snapshot(
            manifest,
            expected_sha256=expected_manifest_sha256,
        ).value
    except ProofManifestError as exc:
        raise FinalizerError(str(exc)) from exc
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise FinalizerError("results manifest lacks provenance metadata")
    snapshot_commit = provenance.get("snapshot_commit")
    if not isinstance(snapshot_commit, str):
        raise FinalizerError("results manifest lacks provenance.snapshot_commit")
    _require_commit(snapshot_commit, "manifest source snapshot commit")
    try:
        require_commit_or_evidence_successor(root, snapshot_commit)
    except GitProvenanceError as exc:
        raise FinalizerError(str(exc)) from exc

    expected_footprint, footprint_sha256 = _load_footprint_csv(
        root / "paper" / "footprint.csv"
    )
    actual_footprint = document.get("footprint_bytes")
    if not isinstance(actual_footprint, dict):
        raise FinalizerError("results manifest lacks footprint_bytes")
    expected_names = {*FOOTPRINT_ARTIFACTS.values(), "note", "platform"}
    actual_names = set(actual_footprint)
    if actual_names != expected_names:
        raise FinalizerError(
            "results manifest footprint_bytes fields differ: "
            f"missing={sorted(expected_names - actual_names)} "
            f"extra={sorted(actual_names - expected_names)}"
        )
    for name in FOOTPRINT_ARTIFACTS.values():
        item = actual_footprint.get(name)
        if not isinstance(item, dict):
            raise FinalizerError(
                f"results manifest footprint entry {name!r} must be an object"
            )
        expected_fields = {"bytes", "kib"}
        actual_fields = set(item)
        if actual_fields != expected_fields:
            raise FinalizerError(
                f"results manifest footprint entry {name!r} fields differ: "
                f"missing={sorted(expected_fields - actual_fields)} "
                f"extra={sorted(actual_fields - expected_fields)}"
            )
        if type(item["bytes"]) is not int:
            raise FinalizerError(
                f"results manifest footprint entry {name!r} field 'bytes' "
                "must be an integer"
            )
        if type(item["kib"]) is not float or not math.isfinite(item["kib"]):
            raise FinalizerError(
                f"results manifest footprint entry {name!r} field 'kib' "
                "must be a finite JSON float"
            )
    if actual_footprint != expected_footprint:
        raise FinalizerError(
            "results manifest footprint_bytes differs from paper/footprint.csv"
        )
    return snapshot_commit, footprint_sha256


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
                "checked-out Git commit does not match expected provenance: "
                f"got {commit_before}, expected {expected_commit}"
            )
        metadata_before = validate_release_metadata(
            root,
            manifest,
            expected_manifest_sha256,
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
        metadata_after = validate_release_metadata(
            root,
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
    if metadata_before != metadata_after:
        raise FinalizerError(
            "release metadata changed while finalizing proof-to-byte provenance"
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
    """Return the scoped local-candidate summary bound to the verified snapshot."""

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
            "PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS "
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
    freeze.add_argument("--expected-git-commit")

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
            expected_commit=args.expected_git_commit,
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
