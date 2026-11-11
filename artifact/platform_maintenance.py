#!/usr/bin/env python3
"""Local Git/source binding for the independent platform maintenance contract."""

from __future__ import annotations

import pathlib

from git_provenance import GitProvenanceError, require_commit_ancestor, run_git_bytes
from platform_distribution_contract import PlatformReleaseProfile
from platform_maintenance_contract import (
    BASE_COHORT_COMMIT,
    PlatformMaintenanceContractError,
    product_contract,
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


def verify_product_source(
    root: pathlib.Path,
    source_commit: str,
    *,
    profile: PlatformReleaseProfile = PlatformReleaseProfile.MAINTENANCE_R2,
) -> None:
    """Keep the maintenance build's product code and locked build inputs at 0.1.5."""

    contract = product_contract(profile)
    load_base_cohort(root)
    try:
        require_commit_ancestor(root, contract.product_commit, source_commit)
        if contract.product_tree is not None:
            observed_tree = run_git_bytes(
                root, ["rev-parse", "--verify", f"{contract.product_commit}^{{tree}}"]
            ).strip()
            if observed_tree != contract.product_tree.encode("ascii"):
                raise PlatformMaintenanceContractError(
                    "reviewed product Git tree differs"
                )
        run_git_bytes(
            root,
            [
                "diff",
                "--exit-code",
                contract.product_commit,
                source_commit,
                "--",
                *contract.product_paths,
            ],
        )
    except GitProvenanceError as exc:
        raise PlatformMaintenanceContractError(
            "maintenance source changed the frozen product or locked build inputs"
        ) from exc
