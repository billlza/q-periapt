#!/usr/bin/env python3
"""Composite versioned publication-receipt contract for all platforms."""

from __future__ import annotations

import apple_publication_contract as apple_contract
import platform_publication_contract as platform_contract


RELEASE_PUBLICATION_KEYS = frozenset(
    platform_contract.PLATFORM_PUBLICATION_KEYS
    | apple_contract.APPLE_PUBLICATION_KEYS
)


class ReleasePublicationContractError(ValueError):
    """A composite publication receipt or selector violates its contract."""


def _fail(message: str) -> None:
    raise ReleasePublicationContractError(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        _fail(f"{label} must be a JSON object with string keys")
    return value


def _publication_entries(manifest: dict[str, object]) -> dict[str, object]:
    publications = manifest.get("release_publications")
    if publications is None:
        return {}
    return _object(publications, "release_publications")


def _filtered_manifest(
    publications: dict[str, object], keys: frozenset[str]
) -> dict[str, object]:
    return {
        "release_publications": {
            key: publications[key] for key in keys if key in publications
        }
    }


def _validate_leaf_dispatch(manifest: dict[str, object]) -> dict[str, object]:
    if not isinstance(manifest, dict):
        _fail("results manifest must be a JSON object")
    publications = _publication_entries(manifest)
    unknown = sorted(set(publications) - RELEASE_PUBLICATION_KEYS)
    if unknown:
        _fail(f"release_publications has unknown entries: {unknown!r}")
    try:
        platform_contract.validate_release_publications(
            _filtered_manifest(
                publications, platform_contract.PLATFORM_PUBLICATION_KEYS
            )
        )
    except platform_contract.PlatformPublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
    try:
        apple_contract.validate_apple_publications(
            _filtered_manifest(
                publications, apple_contract.APPLE_PUBLICATION_KEYS
            )
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
    return publications


def _swift_distribution(manifest: dict[str, object]) -> object | None:
    swift_value = manifest.get("swift_xcframework")
    if swift_value is None:
        return None
    swift = _object(swift_value, "swift_xcframework")
    if "distribution" not in swift:
        return None
    return _object(
        swift["distribution"], "swift_xcframework.distribution"
    )


def _validate_apple_selector_crosslink(
    manifest: dict[str, object], publications: dict[str, object]
) -> None:
    apple_keys = tuple(
        key
        for key in sorted(apple_contract.APPLE_PUBLICATION_KEYS)
        if key in publications
    )
    selector = _swift_distribution(manifest)
    if selector is None and not apple_keys:
        return
    if selector is None:
        _fail(
            "versioned Apple publication receipt requires "
            "swift_xcframework.distribution"
        )
    if not apple_keys:
        _fail(
            "swift_xcframework.distribution requires a versioned Apple "
            "publication receipt"
        )
    matching = []
    for key in apple_keys:
        receipt = _object(publications[key], f"Apple publication receipt {key}")
        if apple_contract.publication_values_equal(
            selector, receipt["distribution"]
        ):
            matching.append(key)
    if len(matching) != 1:
        _fail(
            "swift_xcframework.distribution must exactly match one versioned "
            f"Apple publication receipt; matches={matching!r}"
        )


def validate_release_publications(manifest: dict[str, object]) -> None:
    """Validate the union of platform and Apple receipts plus Apple selector."""

    publications = _validate_leaf_dispatch(manifest)
    _validate_apple_selector_crosslink(manifest, publications)


def _is_exact_legacy_alpha2_selector(manifest: dict[str, object]) -> bool:
    if not isinstance(manifest, dict):
        return False
    publications_value = manifest.get("release_publications")
    if publications_value is None:
        publications: dict[str, object] = {}
    elif isinstance(publications_value, dict):
        publications = publications_value
    else:
        return False
    if any(key in publications for key in apple_contract.APPLE_PUBLICATION_KEYS):
        return False
    selector = _swift_distribution(manifest)
    return apple_contract.publication_values_equal(
        selector, apple_contract.frozen_alpha2_r1_distribution()
    )


def validate_release_publication_transition(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    """Validate monotonic first-parent evolution across all receipt families."""

    legacy_alpha2_migration = _is_exact_legacy_alpha2_selector(previous)
    if legacy_alpha2_migration:
        previous_publications = _validate_leaf_dispatch(previous)
    else:
        validate_release_publications(previous)
        previous_publications = _publication_entries(previous)
    validate_release_publications(current)
    current_publications = _publication_entries(current)

    alpha2_introduced = (
        apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        not in previous_publications
        and apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        in current_publications
    )
    if alpha2_introduced and not legacy_alpha2_migration:
        _fail(
            "historical apple_alpha2_r1 receipt can only be introduced by "
            "the exact legacy Apple alpha.2 selector migration"
        )

    if legacy_alpha2_migration:
        if (
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            not in current_publications
        ):
            _fail(
                "legacy Apple alpha.2 selector migration requires the frozen "
                "apple_alpha2_r1 receipt"
            )
        if not apple_contract.publication_values_equal(
            _swift_distribution(current),
            apple_contract.frozen_alpha2_r1_distribution(),
        ):
            _fail(
                "legacy Apple alpha.2 selector migration must preserve the "
                "exact frozen projection"
            )

    current_platform = _filtered_manifest(
        current_publications, platform_contract.PLATFORM_PUBLICATION_KEYS
    )
    previous_platform = _filtered_manifest(
        previous_publications, platform_contract.PLATFORM_PUBLICATION_KEYS
    )
    try:
        platform_contract.validate_release_publication_transition(
            previous_platform, current_platform
        )
    except platform_contract.PlatformPublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc

    current_apple = _filtered_manifest(
        current_publications, apple_contract.APPLE_PUBLICATION_KEYS
    )
    previous_apple = _filtered_manifest(
        previous_publications, apple_contract.APPLE_PUBLICATION_KEYS
    )
    if legacy_alpha2_migration:
        # The Apple-only contract deliberately has no selector context and
        # therefore forbids every introduction of the frozen alpha.2 leaf.
        # The composite contract owns the sole selector-bound migration and
        # presents that exact frozen leaf as already established while it
        # validates any simultaneous alpha.3 transition.
        previous_apple["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = current_publications[
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ]
    try:
        apple_contract.validate_apple_publication_transition(
            previous_apple, current_apple
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
