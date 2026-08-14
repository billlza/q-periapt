#!/usr/bin/env python3
"""Versioned ABI2 platform publication-receipt dispatcher."""

from __future__ import annotations

import platform_alpha3_publication_contract as alpha3_contract
import platform_release_contract as historical_r2_contract


PLATFORM_R2_PUBLICATION_KEY = (
    historical_r2_contract.PLATFORM_RELEASE_RECEIPT_KEY
)
PLATFORM_ALPHA3_R1_PUBLICATION_KEY = (
    alpha3_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
)
PLATFORM_PUBLICATION_KEYS = frozenset(
    {PLATFORM_R2_PUBLICATION_KEY, PLATFORM_ALPHA3_R1_PUBLICATION_KEY}
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

    if PLATFORM_ALPHA3_R1_PUBLICATION_KEY in publications:
        try:
            alpha3_contract.validate_alpha3_publication_receipt(
                publications[PLATFORM_ALPHA3_R1_PUBLICATION_KEY]
            )
        except alpha3_contract.PlatformAlpha3PublicationContractError as exc:
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

    _require_unchanged_publication(
        previous_publications,
        current_publications,
        PLATFORM_R2_PUBLICATION_KEY,
    )

    if PLATFORM_ALPHA3_R1_PUBLICATION_KEY not in previous_publications:
        return
    if PLATFORM_ALPHA3_R1_PUBLICATION_KEY not in current_publications:
        raise PlatformPublicationContractError(
            "release publication 'platform_alpha3_r1' cannot be removed"
        )

    previous_alpha3 = _object(
        previous_publications[PLATFORM_ALPHA3_R1_PUBLICATION_KEY],
        "previous platform alpha3 publication receipt",
    )
    current_alpha3 = _object(
        current_publications[PLATFORM_ALPHA3_R1_PUBLICATION_KEY],
        "current platform alpha3 publication receipt",
    )
    previous_status = previous_alpha3["status"]
    current_status = current_alpha3["status"]

    if previous_status == alpha3_contract.PLATFORM_ALPHA3_STATUS_VERIFIED:
        if not _json_deep_equal(previous_alpha3, current_alpha3):
            raise PlatformPublicationContractError(
                "verified platform alpha3 publication receipt cannot change"
            )
        return

    if current_status == alpha3_contract.PLATFORM_ALPHA3_STATUS_PENDING:
        if not _json_deep_equal(previous_alpha3, current_alpha3):
            raise PlatformPublicationContractError(
                "pending platform alpha3 publication receipt may only remain "
                "byte-semantically unchanged or advance to verified"
            )
        return

    # Both leaves were validated above, so this is the only remaining state
    # transition: pending -> verified. The publication timestamp and all new
    # verified-only fields may be learned later, but every already-observed fact
    # must remain identical.
    for field in ("boundary", "identity", "kind", "schema_version"):
        if not _json_deep_equal(previous_alpha3[field], current_alpha3[field]):
            raise PlatformPublicationContractError(
                "platform alpha3 pending-to-verified transition changed "
                f"the recorded {field}"
            )
    previous_observation = _object(
        previous_alpha3["observation"],
        "previous platform alpha3 observation",
    )
    current_observation = _object(
        current_alpha3["observation"],
        "current platform alpha3 observation",
    )
    for field in ("source", "candidate_attestation"):
        if not _json_deep_equal(
            previous_observation[field], current_observation[field]
        ):
            raise PlatformPublicationContractError(
                "platform alpha3 pending-to-verified transition changed "
                f"the recorded {field} facts"
            )
    previous_observed_at = alpha3_contract.parse_utc_timestamp(
        previous_observation["observed_at"],
        "previous platform alpha3 observed_at",
    )
    current_observed_at = alpha3_contract.parse_utc_timestamp(
        current_observation["observed_at"],
        "current platform alpha3 observed_at",
    )
    if current_observed_at < previous_observed_at:
        raise PlatformPublicationContractError(
            "platform alpha3 pending-to-verified observed_at moved backwards"
        )
