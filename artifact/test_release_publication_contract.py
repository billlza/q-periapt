#!/usr/bin/env python3
"""Tests for the composite platform and Apple publication contract."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import apple_publication_contract as apple_contract
import release_publication_contract as contract
from test_apple_publication_contract import (
    alpha2_receipt,
    alpha3_pending_receipt,
    alpha3_verified_receipt,
)
from test_platform_alpha3_publication_contract import (
    pending_receipt as platform_alpha3_pending_receipt,
    verified_receipt as platform_alpha3_verified_receipt,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _selector_manifest(
    receipt_key: str,
    receipt: dict[str, object],
    *,
    extra_receipts: dict[str, object] | None = None,
) -> dict[str, object]:
    publications = {receipt_key: receipt}
    if extra_receipts is not None:
        publications.update(extra_receipts)
    return {
        "release_publications": publications,
        "swift_xcframework": {
            "distribution": copy.deepcopy(receipt["distribution"])
        },
    }


class ReleasePublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.legacy_results = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        publications = cls.legacy_results.setdefault(
            "release_publications", {}
        )
        for key in apple_contract.APPLE_PUBLICATION_KEYS:
            publications.pop(key, None)
        cls.legacy_results.setdefault("swift_xcframework", {})[
            "distribution"
        ] = apple_contract.frozen_alpha2_r1_distribution()
        if any(
            key in publications for key in apple_contract.APPLE_PUBLICATION_KEYS
        ) or not apple_contract.publication_values_equal(
            cls.legacy_results["swift_xcframework"]["distribution"],
            apple_contract.frozen_alpha2_r1_distribution(),
        ):
            raise AssertionError(
                "legacy fixture must be the exact selector-only Apple alpha.2 state"
            )
        cls.platform_r2 = copy.deepcopy(
            publications["platform_r2"]
        )

    def test_minimal_absence_and_union_dispatch_are_valid(self) -> None:
        contract.validate_release_publications({})
        apple = alpha2_receipt()
        manifest = _selector_manifest(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            apple,
            extra_receipts={"platform_r2": copy.deepcopy(self.platform_r2)},
        )
        contract.validate_release_publications(manifest)
        self.assertEqual(
            contract.RELEASE_PUBLICATION_KEYS,
            frozenset(
                {
                    "platform_r2",
                    "platform_alpha3_r1",
                    "apple_alpha2_r1",
                    "apple_alpha3_r1",
                }
            ),
        )

    def test_selector_and_versioned_leaf_require_each_other(self) -> None:
        receipt = alpha2_receipt()
        selector_only = {
            "swift_xcframework": {
                "distribution": copy.deepcopy(receipt["distribution"])
            }
        }
        leaf_only = {
            "release_publications": {
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY: receipt
            }
        }
        for label, manifest, message in (
            (
                "selector-only",
                selector_only,
                "requires a versioned Apple publication receipt",
            ),
            (
                "leaf-only",
                leaf_only,
                "requires swift_xcframework.distribution",
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    contract.ReleasePublicationContractError, message
                ):
                    contract.validate_release_publications(manifest)

    def test_selector_matches_exactly_one_apple_leaf(self) -> None:
        alpha2 = alpha2_receipt()
        alpha3 = alpha3_pending_receipt()
        manifest = _selector_manifest(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            alpha2,
            extra_receipts={
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY: alpha3
            },
        )
        contract.validate_release_publications(manifest)

        manifest["swift_xcframework"]["distribution"]["artifact_size"] += 1
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            r"exactly match one.*matches=\[\]",
        ):
            contract.validate_release_publications(manifest)

        # A verified alpha.3 leaf remains distinct from alpha.2, so the
        # historical selector still has exactly one authority.
        distinct = _selector_manifest(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            alpha2,
            extra_receipts={
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY: (
                    alpha3_verified_receipt()
                )
            },
        )
        contract.validate_release_publications(distinct)

    def test_only_exact_legacy_alpha2_projection_has_one_time_migration(self) -> None:
        previous = copy.deepcopy(self.legacy_results)
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "requires a versioned Apple publication receipt",
        ):
            contract.validate_release_publications(previous)

        current = copy.deepcopy(previous)
        current["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()
        contract.validate_release_publication_transition(previous, current)

        with_alpha3 = copy.deepcopy(current)
        with_alpha3["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = alpha3_pending_receipt()
        contract.validate_release_publication_transition(previous, with_alpha3)

        missing_alpha2 = copy.deepcopy(previous)
        missing_alpha2["release_publications"][
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        ] = alpha3_pending_receipt()
        missing_alpha2["swift_xcframework"]["distribution"] = copy.deepcopy(
            missing_alpha2["release_publications"][
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
            ]["distribution"]
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "migration requires the frozen apple_alpha2_r1",
        ):
            contract.validate_release_publication_transition(
                previous, missing_alpha2
            )

        changed_legacy = copy.deepcopy(previous)
        changed_legacy["swift_xcframework"]["distribution"][
            "artifact_size"
        ] += 1
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "requires a versioned Apple publication receipt",
        ):
            contract.validate_release_publication_transition(
                changed_legacy, current
            )

    def test_post_migration_receipts_are_strictly_monotonic(self) -> None:
        alpha2 = alpha2_receipt()
        previous = _selector_manifest(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2
        )
        pending = _selector_manifest(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
            alpha3_pending_receipt(),
            extra_receipts={
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY: copy.deepcopy(
                    alpha2
                )
            },
        )
        current = _selector_manifest(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
            alpha3_verified_receipt(),
            extra_receipts={
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY: copy.deepcopy(
                    alpha2
                )
            },
        )
        contract.validate_release_publication_transition(previous, pending)
        contract.validate_release_publication_transition(pending, current)
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "must first be recorded as pending",
        ):
            contract.validate_release_publication_transition(previous, current)

        removed = copy.deepcopy(current)
        removed["release_publications"].pop(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "alpha.2.*cannot be removed",
        ):
            contract.validate_release_publication_transition(current, removed)

    def test_platform_alpha3_must_be_recorded_pending_before_verified(self) -> None:
        previous = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.platform_r2)
            }
        }
        pending = copy.deepcopy(previous)
        pending["release_publications"]["platform_alpha3_r1"] = (
            platform_alpha3_pending_receipt()
        )
        verified = copy.deepcopy(previous)
        verified["release_publications"]["platform_alpha3_r1"] = (
            platform_alpha3_verified_receipt()
        )

        contract.validate_release_publication_transition(previous, pending)
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "platform alpha3 publication must first be recorded as pending",
        ):
            contract.validate_release_publication_transition(previous, verified)

    def test_historical_platform_r2_cannot_be_added_by_future_transition(self) -> None:
        current = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.platform_r2)
            }
        }
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "historical platform r2 publication cannot be introduced",
        ):
            contract.validate_release_publication_transition({}, current)

    def test_historical_alpha2_cannot_be_added_outside_exact_legacy_migration(
        self,
    ) -> None:
        alpha2 = alpha2_receipt()
        from_empty = _selector_manifest(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            alpha2,
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "only be introduced by the exact legacy",
        ):
            contract.validate_release_publication_transition({}, from_empty)

        alpha3 = alpha3_pending_receipt()
        previous = _selector_manifest(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
            alpha3,
        )
        current = copy.deepcopy(previous)
        current["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "only be introduced by the exact legacy",
        ):
            contract.validate_release_publication_transition(previous, current)

    def test_unknown_union_key_fails_before_leaf_dispatch(self) -> None:
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "unknown entries"
        ):
            contract.validate_release_publications(
                {"release_publications": {"future_publication": {}}}
            )

    def test_non_string_leaf_statuses_are_composite_domain_errors(self) -> None:
        apple_receipt = alpha3_pending_receipt()
        apple_receipt["status"] = []
        apple_manifest = _selector_manifest(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
            apple_receipt,
        )
        platform_receipt = platform_alpha3_pending_receipt()
        platform_receipt["status"] = {}
        platform_manifest = {
            "release_publications": {
                "platform_alpha3_r1": platform_receipt
            }
        }
        historical_receipt = copy.deepcopy(self.platform_r2)
        historical_receipt["status"] = []
        historical_manifest = {
            "release_publications": {"platform_r2": historical_receipt}
        }
        for label, manifest in (
            ("apple", apple_manifest),
            ("platform-alpha3", platform_manifest),
            ("platform-r2", historical_manifest),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                contract.ReleasePublicationContractError,
                "status must be a string",
            ):
                contract.validate_release_publications(manifest)


if __name__ == "__main__":
    unittest.main()
