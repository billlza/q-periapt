#!/usr/bin/env python3
"""Local Git/source binding for the independent platform maintenance contract."""

from __future__ import annotations

import pathlib

from git_provenance import GitProvenanceError, require_commit_ancestor, run_git_bytes
from platform_maintenance_contract import (
    BASE_COHORT_COMMIT,
    BASE_SOURCE_COMMIT,
    PlatformMaintenanceContractError,
    validate_base_cohort_bytes,
)


def load_base_cohort(root: pathlib.Path) -> dict[str, object]:
    """Read the pinned commit locally, without consulting a mutable ref or network."""

    try:
        raw = run_git_bytes(
            root, ["show", f"{BASE_COHORT_COMMIT}:artifact/results.json"]
        )
    except GitProvenanceError as exc:
        raise PlatformMaintenanceContractError(
            "frozen Q is unavailable locally"
        ) from exc
    return validate_base_cohort_bytes(raw)


def verify_product_source(root: pathlib.Path, source_commit: str) -> None:
    """Keep the maintenance build's product code and locked build inputs at 0.1.5."""

    load_base_cohort(root)
    try:
        require_commit_ancestor(root, BASE_SOURCE_COMMIT, source_commit)
        run_git_bytes(
            root,
            [
                "diff",
                "--exit-code",
                BASE_SOURCE_COMMIT,
                source_commit,
                "--",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                ".cargo",
                "crates",
                "bindings/android/jni",
                "bindings/android/src",
            ],
        )
    except GitProvenanceError as exc:
        raise PlatformMaintenanceContractError(
            "maintenance source changed the frozen product or locked build inputs"
        ) from exc
