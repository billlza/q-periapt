#!/usr/bin/env python3
"""Versioned ABI2 platform publication-receipt dispatcher."""

from __future__ import annotations

import platform_stable_publication_contract as stable_contract
import platform_release_contract as historical_r2_contract


PLATFORM_R2_PUBLICATION_KEY = (
    historical_r2_contract.PLATFORM_RELEASE_RECEIPT_KEY
)
PLATFORM_V0_1_1_PUBLICATION_KEY = (
    stable_contract.PLATFORM_V0_1_1_PUBLICATION_KEY
)
PLATFORM_PUBLICATION_KEYS = frozenset(
    {PLATFORM_R2_PUBLICATION_KEY, PLATFORM_V0_1_1_PUBLICATION_KEY}
)


class PlatformPublicationContractError(ValueError):
    """A versioned platform publication receipt violates its contract."""


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        raise PlatformPublicationContractError(
            f"{label} must be a JSON object with string keys"
        )
    return value


def validate_release_publications(manifest: dict[str, object]) -> None:
    """Dispatch exact versioned receipt leaves without weakening either one."""

    if not isinstance(manifest, dict):
        raise PlatformPublicationContractError(
            "results manifest must be a JSON object"
        )
    publications_value = manifest.get("release_publications")
    if publications_value is None:
        return
    publications = _object(publications_value, "release_publications")
    unknown = sorted(set(publications) - PLATFORM_PUBLICATION_KEYS)
    if unknown:
        raise PlatformPublicationContractError(
            f"release_publications has unknown entries: {unknown!r}"
        )

    if PLATFORM_R2_PUBLICATION_KEY in publications:
        historical_receipt = _object(
            publications[PLATFORM_R2_PUBLICATION_KEY],
            "platform r2 publication receipt",
        )
        if not isinstance(historical_receipt.get("status"), str):
            raise PlatformPublicationContractError(
                "platform r2 publication status must be a string"
            )
        try:
            historical_r2_contract.validate_release_publications(
                {
                    "release_publications": {
                        PLATFORM_R2_PUBLICATION_KEY: historical_receipt
                    }
                }
            )
        except historical_r2_contract.PlatformReleaseContractError as exc:
            raise PlatformPublicationContractError(str(exc)) from exc

    if PLATFORM_V0_1_1_PUBLICATION_KEY in publications:
        try:
            stable_contract.validate_v0_1_1_publication_receipt(
                publications[PLATFORM_V0_1_1_PUBLICATION_KEY]
            )
        except stable_contract.PlatformV011PublicationContractError as exc:
            raise PlatformPublicationContractError(str(exc)) from exc


def _publication_entries(
    manifest: dict[str, object],
) -> dict[str, object]:
    publications = manifest.get("release_publications")
    if publications is None:
        return {}
    return _object(publications, "release_publications")


def _json_deep_equal(left: object, right: object) -> bool:
    """Compare already-validated JSON values without Python bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_deep_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_deep_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _require_unchanged_publication(
    previous: dict[str, object],
    current: dict[str, object],
    key: str,
) -> None:
    if key not in previous:
        return
    if key not in current:
        raise PlatformPublicationContractError(
            f"release publication {key!r} cannot be removed"
        )
    if not _json_deep_equal(previous[key], current[key]):
        raise PlatformPublicationContractError(
            f"release publication {key!r} cannot change once recorded"
        )


def validate_release_publication_transition(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    """Validate the monotonic first-parent transition between two manifests.

    This function is intentionally pure: it validates both inputs before
    comparing them and never normalizes or mutates either manifest.
    """

    validate_release_publications(previous)
    validate_release_publications(current)
    previous_publications = _publication_entries(previous)
    current_publications = _publication_entries(current)

    if (
        PLATFORM_R2_PUBLICATION_KEY not in previous_publications
        and PLATFORM_R2_PUBLICATION_KEY in current_publications
    ):
        raise PlatformPublicationContractError(
            "historical platform r2 publication cannot be introduced by a future transition"
        )

    _require_unchanged_publication(
        previous_publications,
        current_publications,
        PLATFORM_R2_PUBLICATION_KEY,
    )

    if PLATFORM_V0_1_1_PUBLICATION_KEY not in previous_publications:
        if PLATFORM_V0_1_1_PUBLICATION_KEY in current_publications:
            current_stable = _object(
                current_publications[PLATFORM_V0_1_1_PUBLICATION_KEY],
                "new platform 0.1.1 publication receipt",
            )
            if (
                current_stable["status"]
                != stable_contract.PLATFORM_V0_1_1_STATUS_PENDING
            ):
                raise PlatformPublicationContractError(
                    "platform 0.1.1 publication must first be recorded as pending"
                )
        return
    if PLATFORM_V0_1_1_PUBLICATION_KEY not in current_publications:
        raise PlatformPublicationContractError(
            "release publication 'platform_v0_1_1' cannot be removed"
        )

    previous_stable = _object(
        previous_publications[PLATFORM_V0_1_1_PUBLICATION_KEY],
        "previous platform 0.1.1 publication receipt",
    )
    current_stable = _object(
        current_publications[PLATFORM_V0_1_1_PUBLICATION_KEY],
        "current platform 0.1.1 publication receipt",
    )
    previous_status = previous_stable["status"]
    current_status = current_stable["status"]

    if previous_status == stable_contract.PLATFORM_V0_1_1_STATUS_VERIFIED:
        if not _json_deep_equal(previous_stable, current_stable):
            raise PlatformPublicationContractError(
                "verified platform 0.1.1 publication receipt cannot change"
            )
        return

    if current_status == stable_contract.PLATFORM_V0_1_1_STATUS_PENDING:
        if not _json_deep_equal(previous_stable, current_stable):
            raise PlatformPublicationContractError(
                "pending platform 0.1.1 publication receipt may only remain "
                "byte-semantically unchanged or advance to verified"
            )
        return

    # Both leaves were validated above, so this is the only remaining state
    # transition: pending -> verified. The publication timestamp and all new
    # verified-only fields may be learned later, but every already-observed fact
    # must remain identical.
    for field in ("boundary", "identity", "kind", "schema_version"):
        if not _json_deep_equal(previous_stable[field], current_stable[field]):
            raise PlatformPublicationContractError(
                "platform 0.1.1 pending-to-verified transition changed "
                f"the recorded {field}"
            )
    previous_observation = _object(
        previous_stable["observation"],
        "previous platform 0.1.1 observation",
    )
    current_observation = _object(
        current_stable["observation"],
        "current platform 0.1.1 observation",
    )
    for field in ("source", "candidate_attestation", "release_candidate"):
        if not _json_deep_equal(
            previous_observation[field], current_observation[field]
        ):
            raise PlatformPublicationContractError(
                "platform 0.1.1 pending-to-verified transition changed "
                f"the recorded {field} facts"
            )
    previous_observed_at = stable_contract.parse_utc_timestamp(
        previous_observation["observed_at"],
        "previous platform 0.1.1 observed_at",
    )
    current_observed_at = stable_contract.parse_utc_timestamp(
        current_observation["observed_at"],
        "current platform 0.1.1 observed_at",
    )
    if current_observed_at < previous_observed_at:
        raise PlatformPublicationContractError(
            "platform 0.1.1 pending-to-verified observed_at moved backwards"
        )
