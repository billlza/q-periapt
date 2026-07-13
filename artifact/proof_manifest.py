#!/usr/bin/env python3
"""Strict results-manifest loading and atomic selected-proof binding."""

from __future__ import annotations

import os
import pathlib
import re
from dataclasses import dataclass

from evidence_io import (
    EvidenceIOError,
    JsonObjectSnapshot,
    load_json_object_snapshot,
)


MAX_RESULTS_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SELECTED_PROOF_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PERFORMANCE_SOURCE_STATUSES = {
    "current_controlled_pass",
    "stale_requires_rerun",
}
APPLE_SOURCE_STATUSES = {
    "current_dirty_diagnostic_pass",
    "stale_requires_rerun",
}
ANDROID_SOURCE_STATUSES = {
    "current_clean_tree_emulator_pass",
    "current_clean_tree_physical_pass",
    "stale_requires_rerun",
}


class ProofManifestError(ValueError):
    """A results manifest or selected-proof binding is invalid."""


@dataclass(frozen=True, slots=True)
class BindingSpec:
    section: str
    path_key: str
    hash_key: str


BINDINGS = {
    "apple_device": BindingSpec(
        section="apple_device",
        path_key="current_dirty_proof_path",
        hash_key="current_dirty_proof_sha256",
    ),
    "apple_matrix": BindingSpec(
        section="apple_device",
        path_key="matrix_proof_path",
        hash_key="matrix_proof_sha256",
    ),
    "android_runtime": BindingSpec(
        section="android_device_runtime",
        path_key="proof_path",
        hash_key="proof_sha256",
    ),
    "performance": BindingSpec(
        section="performance",
        path_key="proof_path",
        hash_key="proof_sha256",
    ),
}


def _validate_binding_declaration(section: dict[str, object], binding: str) -> None:
    spec = BINDINGS[binding]
    relative = section.get(spec.path_key)
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ProofManifestError(
            f"current {binding} status requires a canonical selected-proof path"
        )
    pure = pathlib.PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
        or pure.as_posix() != relative
        or any(part in ("", ".") for part in pure.parts)
    ):
        raise ProofManifestError(
            f"current {binding} status requires a canonical selected-proof path"
        )
    digest = section.get(spec.hash_key)
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise ProofManifestError(
            f"current {binding} status requires a selected-proof SHA-256"
        )


def _validate_optional_status(
    section: dict[str, object],
    key: str,
    allowed: set[str],
) -> None:
    value = section.get(key)
    if value is not None and value not in allowed:
        raise ProofManifestError(
            f"results manifest {key} has unknown status: {value!r}"
        )


def validate_declared_currentness(manifest: dict[str, object]) -> None:
    """Prevent prose/status fields from promoting stale selected evidence."""

    root_digest = manifest.get("proof_source_tree_sha256")
    if root_digest is not None and (
        not isinstance(root_digest, str) or SHA256_RE.fullmatch(root_digest) is None
    ):
        raise ProofManifestError("results manifest canonical source digest is malformed")

    performance = manifest.get("performance")
    if isinstance(performance, dict):
        _validate_optional_status(
            performance,
            "current_source_status",
            PERFORMANCE_SOURCE_STATUSES,
        )
    if isinstance(performance, dict) and performance.get("current_source_status") == "current_controlled_pass":
        _validate_binding_declaration(performance, "performance")
        if performance.get("proof_schema") != 4:
            raise ProofManifestError("current performance status requires proof schema 4")
        if root_digest is None or performance.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current performance status does not match the manifest source digest")
        if performance.get("status") != "pass":
            raise ProofManifestError("current performance status requires a passing proof")
        if not isinstance(performance.get("proof_generated_at"), str):
            raise ProofManifestError("current performance status requires proof generation time")

    apple = manifest.get("apple_device")
    if isinstance(apple, dict):
        _validate_optional_status(
            apple,
            "current_source_status",
            APPLE_SOURCE_STATUSES,
        )
        _validate_optional_status(
            apple,
            "matrix_source_status",
            APPLE_SOURCE_STATUSES,
        )
    if isinstance(apple, dict) and apple.get("current_source_status") == "current_dirty_diagnostic_pass":
        _validate_binding_declaration(apple, "apple_device")
        if apple.get("current_dirty_proof_schema") != 2:
            raise ProofManifestError("current Apple diagnostic requires proof schema 2")
        if root_digest is None or apple.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current Apple diagnostic does not match the manifest source digest")
        attempt = apple.get("current_attempt")
        if not isinstance(attempt, dict) or attempt.get("status") != "pass" or attempt.get("proof_emitted") is not True:
            raise ProofManifestError("current Apple diagnostic requires a passing emitted-proof attempt")
        if not isinstance(apple.get("current_dirty_proof_generated_at"), str):
            raise ProofManifestError("current Apple diagnostic requires proof generation time")

    if isinstance(apple, dict) and apple.get("matrix_source_status") == "current_dirty_diagnostic_pass":
        _validate_binding_declaration(apple, "apple_matrix")
        if apple.get("matrix_proof_schema") != 3:
            raise ProofManifestError("current Apple matrix requires proof schema 3")
        if root_digest is None or apple.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current Apple matrix does not match the manifest source digest")
        if apple.get("matrix_status") != "pass":
            raise ProofManifestError("current Apple matrix requires a passing proof")
        if not isinstance(apple.get("matrix_generated_at"), str):
            raise ProofManifestError("current Apple matrix requires proof generation time")

    android = manifest.get("android_device_runtime")
    if isinstance(android, dict):
        _validate_optional_status(
            android,
            "current_source_status",
            ANDROID_SOURCE_STATUSES,
        )
    if isinstance(android, dict) and android.get("current_source_status") in {
        "current_clean_tree_emulator_pass",
        "current_clean_tree_physical_pass",
    }:
        _validate_binding_declaration(android, "android_runtime")
        if android.get("proof_schema") != 2:
            raise ProofManifestError("current Android runtime status requires proof schema 2")
        if root_digest is None or android.get("proof_source_tree_sha256") != root_digest:
            raise ProofManifestError("current Android runtime status does not match the manifest source digest")
        if android.get("status") != "pass":
            raise ProofManifestError("current Android runtime status requires a passing proof")
        if not isinstance(android.get("proof_generated_at"), str):
            raise ProofManifestError("current Android runtime status requires proof generation time")


def load_results_manifest_snapshot(
    path: pathlib.Path,
    *,
    expected_sha256: str | None = None,
) -> JsonObjectSnapshot:
    """Strict-load results.json and optionally pin it to a startup digest."""

    try:
        snapshot = load_json_object_snapshot(
            path,
            maximum=MAX_RESULTS_MANIFEST_BYTES,
            label="results manifest",
        )
    except EvidenceIOError as exc:
        raise ProofManifestError(str(exc)) from exc
    validate_declared_currentness(snapshot.value)
    if expected_sha256 is not None:
        if SHA256_RE.fullmatch(expected_sha256) is None:
            raise ProofManifestError("expected results manifest SHA-256 is malformed")
        if snapshot.file.sha256 != expected_sha256:
            raise ProofManifestError(
                "results manifest changed during proof-to-byte run: "
                f"got {snapshot.file.sha256}, expected {expected_sha256}"
            )
    return snapshot


def _safe_declared_path(root: pathlib.Path, relative: object) -> pathlib.Path:
    if not isinstance(relative, str) or not relative:
        raise ProofManifestError("results manifest proof path is missing")
    if "\\" in relative:
        raise ProofManifestError(f"results manifest proof path is not canonical POSIX: {relative}")
    pure = pathlib.PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ProofManifestError(f"unsafe results manifest proof path: {relative}")
    if pure.as_posix() != relative or any(part in ("", ".") for part in pure.parts):
        raise ProofManifestError(f"non-canonical results manifest proof path: {relative}")
    declared = root.joinpath(*pure.parts)
    lexical = pathlib.Path(os.path.abspath(declared))
    root_lexical = pathlib.Path(os.path.abspath(root))
    try:
        lexical.relative_to(root_lexical)
    except ValueError as exc:
        raise ProofManifestError(f"results manifest proof path escapes repository: {relative}") from exc
    return lexical


def select_bound_json_snapshot(
    root: pathlib.Path,
    manifest: JsonObjectSnapshot,
    *,
    binding: str,
    selected_path: pathlib.Path,
    maximum: int = MAX_SELECTED_PROOF_BYTES,
    label: str,
) -> JsonObjectSnapshot:
    """Hash-check and strict-parse one selected proof from the same bytes."""

    spec = BINDINGS.get(binding)
    if spec is None:
        raise ProofManifestError(f"unknown proof binding: {binding}")
    section = manifest.value.get(spec.section)
    if not isinstance(section, dict):
        raise ProofManifestError(f"results manifest lacks section {spec.section}")
    declared = _safe_declared_path(root, section.get(spec.path_key))
    expected_sha256 = section.get(spec.hash_key)
    if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
        raise ProofManifestError(
            f"results manifest has invalid {spec.section}.{spec.hash_key}"
        )

    selected = selected_path if selected_path.is_absolute() else root / selected_path
    selected_lexical = pathlib.Path(os.path.abspath(selected))
    if selected_lexical != declared:
        raise ProofManifestError(
            "selected proof differs from results manifest: "
            f"selected={selected_lexical} declared={declared}"
        )
    try:
        snapshot = load_json_object_snapshot(
            selected_lexical,
            maximum=maximum,
            label=label,
        )
    except EvidenceIOError as exc:
        raise ProofManifestError(str(exc)) from exc
    if snapshot.file.sha256 != expected_sha256:
        raise ProofManifestError(
            "selected proof hash differs from results manifest: "
            f"got={snapshot.file.sha256} expected={expected_sha256}"
        )
    return snapshot
