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
from test_release_publication_contract import frozen_baseline_manifest


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
        results = frozen_baseline_manifest()
        cls.historical_r2 = results["release_publications"]["platform_r2"]

    def test_historical_r2_and_versioned_stable_coexist(self) -> None:
        manifest = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2),
                "platform_v0_1_5": pending_receipt(),
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
            {"release_publications": {"platform_v0_1_5": pending_receipt()}}
        )

    def test_frozen_v0_1_3_receipt_freezes_the_committed_receipt(self) -> None:
        results = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        # Every committed manifest state on and after the published 0.1.3
        # line carries the frozen verified leaf, so a direct comparison
        # against the live manifest is exact and self-maintaining.
        live = results["release_publications"][
            contract.PLATFORM_V0_1_3_PUBLICATION_KEY
        ]
        frozen = contract.frozen_platform_v0_1_3_receipt()
        self.assertEqual(
            json.dumps(frozen, sort_keys=True, indent=2, ensure_ascii=True),
            json.dumps(live, sort_keys=True, indent=2, ensure_ascii=True),
        )
        contract.validate_release_publications(
            {
                "release_publications": {
                    "platform_r2": copy.deepcopy(self.historical_r2),
                    "platform_v0_1_3": frozen,
                }
            }
        )

    def test_near_frozen_receipts_fail_closed(self) -> None:
        # Deep equality with the frozen receipt is now the platform_v0_1_3
        # key's only accepting path; the structural machinery belongs to
        # the platform_v0_1_5 family.
        invalid = contract.frozen_platform_v0_1_3_receipt()
        invalid["identity"]["distribution_revision"] = "r2"
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "frozen platform 0.1.3.*differs from the published history",
        ):
            contract.validate_release_publications(
                {"release_publications": {"platform_v0_1_3": invalid}}
            )

    def test_frozen_v0_1_3_transitions_forbid_introduce_remove_change(
        self,
    ) -> None:
        empty: dict[str, object] = {}
        frozen = {
            "release_publications": {
                "platform_v0_1_3": contract.frozen_platform_v0_1_3_receipt()
            }
        }
        contract.validate_release_publication_transition(
            frozen, copy.deepcopy(frozen)
        )
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "frozen platform 0.1.3.*cannot be introduced",
        ):
            contract.validate_release_publication_transition(empty, frozen)
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "cannot be removed",
        ):
            contract.validate_release_publication_transition(frozen, empty)
        # Deep equality with the frozen receipt is the platform_v0_1_3
        # key's only accepting path, so a changed or demoted leaf already
        # fails closed at validation, before any transition comparison.
        changed = copy.deepcopy(frozen)
        changed["release_publications"]["platform_v0_1_3"]["observation"][
            "release_id"
        ] += 1
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "frozen platform 0.1.3.*differs from the published history",
        ):
            contract.validate_release_publication_transition(frozen, changed)
        demoted = {
            "release_publications": {"platform_v0_1_3": pending_receipt()}
        }
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "frozen platform 0.1.3.*differs from the published history",
        ):
            contract.validate_release_publication_transition(frozen, demoted)

    def test_dispatch_keys_are_exact_versioned_leaf_names(self) -> None:
        # platform_v0_1_4 remains a recognizable historical identity, but no
        # occurrence is admissible until this source line installs exact frozen
        # receipt bytes for it.
        self.assertEqual(
            contract.PLATFORM_PUBLICATION_KEYS,
            frozenset(
                {
                    "platform_r2",
                    "platform_v0_1_3",
                    "platform_v0_1_4",
                    "platform_v0_1_5",
                }
            ),
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

    def test_v0_1_4_is_rejected_until_its_frozen_image_is_installed(
        self,
    ) -> None:
        valid_current = {
            "release_publications": {
                contract.PLATFORM_V0_1_5_PUBLICATION_KEY: pending_receipt()
            }
        }
        contract.validate_release_publications(valid_current)

        for label, unavailable_leaf in (
            ("arbitrary", {"arbitrary": True}),
            ("null", None),
            ("wrong-family", pending_receipt()),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                contract.PlatformPublicationContractError,
                "platform 0.1.4.*frozen receipt image is unavailable",
            ):
                contract.validate_release_publications(
                    {
                        "release_publications": {
                            contract.PLATFORM_V0_1_4_PUBLICATION_KEY: (
                                unavailable_leaf
                            )
                        }
                    }
                )

        preserved = {
            "release_publications": {
                contract.PLATFORM_V0_1_4_PUBLICATION_KEY: {
                    "arbitrary": True
                }
            }
        }
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "platform 0.1.4.*frozen receipt image is unavailable",
        ):
            contract.validate_release_publication_transition(
                preserved,
                copy.deepcopy(preserved),
            )

    def test_leaf_errors_are_reported_through_one_aggregator_boundary(self) -> None:
        stable = pending_receipt()
        stable["identity"]["distribution_revision"] = "r2"
        with self.assertRaisesRegex(
            contract.PlatformPublicationContractError,
            "v0_1_5 publication identity differs",
        ):
            contract.validate_release_publications(
                {"release_publications": {"platform_v0_1_5": stable}}
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
                "platform_v0_1_5": pending_receipt()
            }
        }
        stable_verified = {
            "release_publications": {
                "platform_v0_1_5": verified_receipt()
            }
        }
        both = {
            "release_publications": {
                "platform_r2": copy.deepcopy(self.historical_r2),
                "platform_v0_1_5": pending_receipt(),
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
                "platform_v0_1_5": pending_receipt()
            }
        }
        stable_verified = {
            "release_publications": {
                "platform_v0_1_5": verified_receipt()
            }
        }

        changed_pending = copy.deepcopy(stable_pending)
        changed_pending["release_publications"]["platform_v0_1_5"][
            "observation"
        ]["observed_at"] = "2026-08-14T05:00:00Z"
        changed_verified = copy.deepcopy(stable_verified)
        changed_verified["release_publications"]["platform_v0_1_5"][
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
                "platform_v0_1_5": pending_receipt()
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
                                "platform_v0_1_5": promoted
                            }
                        },
                    )

        promoted = verified_receipt()
        promoted["observation"]["observed_at"] = "2026-08-14T05:00:00Z"
        contract.validate_release_publication_transition(
            previous,
            {
                "release_publications": {
                    "platform_v0_1_5": promoted
                }
            },
        )

    def test_pending_to_verified_observed_at_is_monotonic(self) -> None:
        previous = {
            "release_publications": {
                "platform_v0_1_5": pending_receipt()
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
                            "platform_v0_1_5": promoted
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
                        "platform_v0_1_5": earlier
                    }
                },
            )

    def test_transition_validates_both_leaf_sets_before_comparing(self) -> None:
        invalid = {
            "release_publications": {
                "platform_v0_1_5": pending_receipt(),
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
