#!/usr/bin/env python3
"""Tests for coexistence of immutable platform publication receipts."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import platform_publication_contract as contract
import platform_release_contract as historical_contract
from test_platform_stable_publication_contract import pending_receipt
from test_platform_stable_publication_contract import verified_receipt


ROOT = pathlib.Path(__file__).resolve().parents[1]


def historical_r2_pending(receipt: dict[str, object]) -> dict[str, object]:
    pending = copy.deepcopy(receipt)
    pending["status"] = historical_contract.PLATFORM_RELEASE_STATUS_PENDING
    observation = pending["observation"]
    observation["fresh_download_verified"] = False
    observation["deep_distribution_verified"] = False
    observation["release_asset_verification_count"] = 0
    observation["candidate_attestation"]["verified"] = False
    observation["candidate_attestation"]["subjects"] = []
    observation["release_attestation"]["verified"] = False
    observation["release_attestation"]["subjects"] = []
    observation["release_attestation"]["verification_record_sha256"] = None
    return pending


class PlatformPublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        results = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        cls.historical_r2 = results["release_publications"]["platform_r2"]

    def test_historical_r2_and_versioned_stable_coexist(self) -> None:
        manifest = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2),
                "platform_v0_1_1": pending_receipt(),
            }
        }
        contract.validate_release_publications(manifest)
        contract.validate_release_publications(
            {
                "release_publications": {
                    "platform_r2": copy.deepcopy(self.historical_r2)
                }
            }
        )
        contract.validate_release_publications(
            {"release_publications": {"platform_v0_1_1": pending_receipt()}}
        )

    def test_dispatch_keys_are_exact_versioned_leaf_names(self) -> None:
        self.assertEqual(
            contract.PLATFORM_PUBLICATION_KEYS,
            frozenset({"platform_r2", "platform_v0_1_1"}),
        )
        for key in (
            "platform_v0_1_0_r1",
            "platform_v0_1_0_r2",
            "platform_r3",
        ):
            with self.subTest(key=key):
                with self.assertRaisesRegex(
                    contract.PlatformPublicationContractError,
                    "unknown entries",
                ):
                    contract.validate_release_publications(
                        {"release_publications": {key: {}}}
                    )

    def test_leaf_errors_are_reported_through_one_aggregator_boundary(self) -> None:
        stable = pending_receipt()
        stable["identity"]["distribution_revision"] = "r2"
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "v0_1_1 publication identity differs",
        ):
            contract.validate_release_publications(
                {"release_publications": {"platform_v0_1_1": stable}}
            )

        historical = copy.deepcopy(self.historical_r2)
        historical["identity"]["distribution_revision"] = "r3"
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "platform r2 publication identity differs",
        ):
            contract.validate_release_publications(
                {"release_publications": {"platform_r2": historical}}
            )

        for invalid_status in ([], {}):
            with self.subTest(
                historical_status=type(invalid_status).__name__
            ):
                historical = copy.deepcopy(self.historical_r2)
                historical["status"] = invalid_status
                with self.assertRaisesRegex(
                    contract.PlatformPublicationContractError,
                    "status must be a string",
                ):
                    contract.validate_release_publications(
                        {
                            "release_publications": {
                                "platform_r2": historical
                            }
                        }
                    )

    def test_optional_container_preserves_historical_absence_semantics(self) -> None:
        contract.validate_release_publications({})
        contract.validate_release_publications({"release_publications": None})
        contract.validate_release_publications({"release_publications": {}})
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "JSON object",
        ):
            contract.validate_release_publications(
                {"release_publications": []}
            )

    def test_transition_allows_only_monotonic_leaf_additions(self) -> None:
        empty: dict[str, object] = {}
        r2 = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2)
            }
        }
        stable_pending = {
            "release_publications": {
                "platform_v0_1_1": pending_receipt()
            }
        }
        stable_verified = {
            "release_publications": {
                "platform_v0_1_1": verified_receipt()
            }
        }
        both = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2),
                "platform_v0_1_1": pending_receipt(),
            }
        }

        for label, previous, current in (
            ("empty", empty, empty),
            ("add-stable-pending", empty, stable_pending),
            ("same-r2", r2, copy.deepcopy(r2)),
            (
                "same-stable-pending",
                stable_pending,
                copy.deepcopy(stable_pending),
            ),
            (
                "same-stable-verified",
                stable_verified,
                copy.deepcopy(stable_verified),
            ),
            ("pending-to-verified", stable_pending, stable_verified),
        ):
            with self.subTest(label=label):
                contract.validate_release_publication_transition(
                    previous, current
                )

        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "must first be recorded as pending",
        ):
            contract.validate_release_publication_transition(
                empty, stable_verified
            )

        for label, current in (("add-r2", r2), ("add-both", both)):
            with self.subTest(label=label), self.assertRaisesRegex(
                contract.PlatformPublicationContractError,
                "historical platform r2 publication cannot be introduced",
            ):
                contract.validate_release_publication_transition(empty, current)

    def test_transition_rejects_removal_or_change_of_recorded_receipts(self) -> None:
        r2_verified = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2)
            }
        }
        r2_pending = {
            "release_publications": {
                "platform_r2": historical_r2_pending(self.historical_r2)
            }
        }
        stable_pending = {
            "release_publications": {
                "platform_v0_1_1": pending_receipt()
            }
        }
        stable_verified = {
            "release_publications": {
                "platform_v0_1_1": verified_receipt()
            }
        }

        changed_pending = copy.deepcopy(stable_pending)
        changed_pending["release_publications"]["platform_v0_1_1"][
            "observation"
        ]["observed_at"] = "2026-08-14T05:00:00Z"
        changed_verified = copy.deepcopy(stable_verified)
        changed_verified["release_publications"]["platform_v0_1_1"][
            "observation"
        ]["release_id"] += 1
        for label, previous, current, message in (
            ("remove-r2", r2_verified, {}, "cannot be removed"),
            (
                "change-r2",
                r2_verified,
                r2_pending,
                "cannot change once recorded",
            ),
            ("remove-stable", stable_pending, {}, "cannot be removed"),
            (
                "change-pending",
                stable_pending,
                changed_pending,
                "only remain.*unchanged",
            ),
            (
                "verified-to-pending",
                stable_verified,
                stable_pending,
                "verified.*cannot change",
            ),
            (
                "change-verified",
                stable_verified,
                changed_verified,
                "verified.*cannot change",
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    contract.PlatformPublicationContractError, message
                ):
                    contract.validate_release_publication_transition(
                        previous, current
                    )

    def test_pending_to_verified_preserves_all_previously_observed_facts(
        self,
    ) -> None:
        previous = {
            "release_publications": {
                "platform_v0_1_1": pending_receipt()
            }
        }
        for label, mutate in (
            (
                "source",
                lambda receipt: receipt["observation"]["source"].update(
                    {
                        "canonical_source_tree_sha256": "9" * 64,
                    }
                ),
            ),
            (
                "candidate",
                lambda receipt: receipt["observation"][
                    "candidate_attestation"
                ].update({"verification_record_sha256": "8" * 64}),
            ),
            (
                "release-candidate",
                lambda receipt: (
                    receipt["observation"]["release_candidate"][
                        "android_runtime_evidence"
                    ].update({"proof_sha256": "7" * 64}),
                    receipt["observation"]["android_runtime_evidence"].update(
                        {"proof_sha256": "7" * 64}
                    ),
                ),
            ),
        ):
            with self.subTest(label=label):
                promoted = verified_receipt()
                mutate(promoted)
                with self.assertRaisesRegex(
                    contract.PlatformPublicationContractError,
                    "pending-to-verified.*changed",
                ):
                    contract.validate_release_publication_transition(
                        previous,
                        {
                            "release_publications": {
                                "platform_v0_1_1": promoted
                            }
                        },
                    )

        promoted = verified_receipt()
        promoted["observation"]["observed_at"] = "2026-08-14T05:00:00Z"
        contract.validate_release_publication_transition(
            previous,
            {
                "release_publications": {
                    "platform_v0_1_1": promoted
                }
            },
        )

    def test_pending_to_verified_observed_at_is_monotonic(self) -> None:
        previous = {
            "release_publications": {
                "platform_v0_1_1": pending_receipt()
            }
        }

        for label, observed_at in (
            ("equal", "2026-08-14T04:00:00Z"),
            ("later", "2026-08-14T05:00:00Z"),
        ):
            with self.subTest(label=label):
                promoted = verified_receipt()
                promoted["observation"]["observed_at"] = observed_at
                contract.validate_release_publication_transition(
                    previous,
                    {
                        "release_publications": {
                            "platform_v0_1_1": promoted
                        }
                    },
                )

        earlier = verified_receipt()
        earlier["observation"]["observed_at"] = "2026-08-14T03:30:00Z"
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "observed_at moved backwards",
        ):
            contract.validate_release_publication_transition(
                previous,
                {
                    "release_publications": {
                        "platform_v0_1_1": earlier
                    }
                },
            )

    def test_transition_validates_both_leaf_sets_before_comparing(self) -> None:
        invalid = {
            "release_publications": {
                "platform_v0_1_1": pending_receipt(),
                "unexpected": {},
            }
        }
        for previous, current in ((invalid, {}), ({}, invalid)):
            with self.subTest(previous_invalid=previous is invalid):
                with self.assertRaisesRegex(
                    contract.PlatformPublicationContractError,
                    "unknown entries",
                ):
                    contract.validate_release_publication_transition(
                        previous, current
                    )


if __name__ == "__main__":
    unittest.main()
