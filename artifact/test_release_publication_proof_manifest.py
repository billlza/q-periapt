#!/usr/bin/env python3
"""Proof-manifest wiring tests for versioned Apple publication selectors."""

from __future__ import annotations

import copy
import unittest

import apple_publication_contract as apple_contract
import proof_manifest
import release_publication_contract
from test_apple_publication_contract import (
    alpha2_receipt,
    alpha3_pending_receipt,
)
from test_platform_alpha3_publication_contract import (
    pending_receipt as platform_alpha3_pending_receipt,
)


def _manifest_with_selector(
    key: str, receipt: dict[str, object]
) -> dict[str, object]:
    return {
        "release_publications": {key: receipt},
        "swift_xcframework": {
            "distribution": copy.deepcopy(receipt["distribution"])
        },
    }


class ReleasePublicationProofManifestTests(unittest.TestCase):
    def test_versioned_apple_selector_is_accepted_by_proof_manifest(self) -> None:
        for key, receipt in (
            (apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY, alpha2_receipt()),
            (
                apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
                alpha3_pending_receipt(),
            ),
        ):
            with self.subTest(key=key):
                proof_manifest.validate_declared_currentness(
                    _manifest_with_selector(key, receipt)
                )

    def test_proof_manifest_rejects_selector_or_leaf_as_independent_authority(
        self,
    ) -> None:
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
        for label, manifest in (
            ("selector-only", selector_only),
            ("leaf-only", leaf_only),
        ):
            with self.subTest(label=label):
                with self.assertRaises(proof_manifest.ProofManifestError):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_proof_manifest_rejects_selector_leaf_drift(self) -> None:
        receipt = alpha3_pending_receipt()
        manifest = _manifest_with_selector(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY, receipt
        )
        manifest["swift_xcframework"]["distribution"]["artifact_size"] += 1
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "exactly match one"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_non_string_publication_statuses_are_manifest_domain_errors(
        self,
    ) -> None:
        apple_receipt = alpha3_pending_receipt()
        apple_receipt["status"] = []
        apple_manifest = _manifest_with_selector(
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
        for label, manifest in (
            ("apple", apple_manifest),
            ("platform-alpha3", platform_manifest),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                proof_manifest.ProofManifestError,
                "status must be a string",
            ):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_currentness_shape_does_not_authorize_frozen_leaf_insertion(
        self,
    ) -> None:
        pending = alpha3_pending_receipt()
        previous = _manifest_with_selector(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY,
            pending,
        )
        current = copy.deepcopy(previous)
        current["release_publications"][
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
        ] = alpha2_receipt()

        # Both snapshots are structurally current; only the state transition
        # has enough context to reject a newly invented historical leaf.
        proof_manifest.validate_declared_currentness(previous)
        proof_manifest.validate_declared_currentness(current)
        with self.assertRaisesRegex(
            release_publication_contract.ReleasePublicationContractError,
            "only be introduced by the exact legacy",
        ):
            release_publication_contract.validate_release_publication_transition(
                previous,
                current,
            )


if __name__ == "__main__":
    unittest.main()
