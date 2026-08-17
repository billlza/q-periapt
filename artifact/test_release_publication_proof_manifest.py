#!/usr/bin/env python3
"""Proof-manifest wiring tests for the coordinated stable cohort."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import apple_publication_contract as apple_contract
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
import proof_manifest
import release_publication_contract as contract
from test_apple_publication_contract import (
    stable_pending_receipt,
    stable_verified_receipt,
)
from test_crates_io_publication_contract import receipt_fixture as crates_receipt
from test_platform_stable_publication_contract import (
    pending_receipt as platform_pending_receipt,
    verified_receipt as platform_verified_receipt,
)
from test_release_publication_contract import (
    _rebind_crates,
    _rebind_platform,
    source_manifest_fixture,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _source_manifest() -> dict[str, object]:
    legacy = json.loads(
        (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
    )
    source_manifest = source_manifest_fixture(legacy)
    source = stable_pending_receipt()["source"]
    return {
        "android_aar": copy.deepcopy(source_manifest["android_aar"]),
        "android_physical_runtime": copy.deepcopy(
            source_manifest["android_physical_runtime"]
        ),
        "performance": copy.deepcopy(source_manifest["performance"]),
        "proof_source_tree_sha256": source[
            "canonical_source_tree_sha256"
        ],
        "provenance": {"snapshot_commit": source["source_parent_commit"]},
        "release_publications": copy.deepcopy(
            legacy["release_publications"]
        ),
        "rust_publish": copy.deepcopy(source_manifest["rust_publish"]),
        "swift_xcframework": contract.neutral_swift_selector(legacy),
    }


def _pending_manifest() -> dict[str, object]:
    manifest = _source_manifest()
    apple = stable_pending_receipt()
    source = apple["source"]
    manifest["release_publications"][
        apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
    ] = apple
    manifest["release_publications"][
        platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY
    ] = _rebind_platform(platform_pending_receipt(), source)
    return manifest


def _verified_manifest() -> dict[str, object]:
    manifest = _pending_manifest()
    apple = stable_verified_receipt()
    source = apple["source"]
    publications = manifest["release_publications"]
    publications[apple_contract.APPLE_V0_1_0_PUBLICATION_KEY] = apple
    publications[platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY] = (
        _rebind_platform(platform_verified_receipt(), source)
    )
    publications[crates_contract.CRATES_IO_PUBLICATION_KEY] = _rebind_crates(
        crates_receipt(10), source, manifest["rust_publish"]
    )
    manifest["swift_xcframework"]["active_publication_key"] = (
        apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
    )
    manifest["swift_xcframework"]["distribution"] = copy.deepcopy(
        apple["distribution"]
    )
    return manifest


class ReleasePublicationProofManifestTests(unittest.TestCase):
    def test_all_three_cohort_states_are_accepted_by_proof_manifest(self) -> None:
        for manifest in (_source_manifest(), _pending_manifest(), _verified_manifest()):
            with self.subTest(state=contract.publication_state(manifest)):
                proof_manifest.validate_declared_currentness(manifest)

    def test_selector_and_leaf_are_not_independent_authorities(self) -> None:
        source = _source_manifest()
        selector_only = {"swift_xcframework": source["swift_xcframework"]}
        leaf_only = {
            "release_publications": copy.deepcopy(source["release_publications"])
        }
        for label, manifest in (("selector", selector_only), ("leaf", leaf_only)):
            with self.subTest(label=label), self.assertRaises(
                proof_manifest.ProofManifestError
            ):
                proof_manifest.validate_declared_currentness(manifest)

    def test_proof_manifest_rejects_pending_activation_and_source_drift(self) -> None:
        pending = _pending_manifest()
        pending["swift_xcframework"]["active_publication_key"] = (
            apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
        )
        pending["swift_xcframework"]["distribution"] = copy.deepcopy(
            pending["release_publications"][
                apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
            ]["distribution"]
        )
        with self.assertRaises(proof_manifest.ProofManifestError):
            proof_manifest.validate_declared_currentness(pending)

        mismatched = _verified_manifest()
        mismatched["proof_source_tree_sha256"] = "f" * 64
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "manifest root|source digest"
        ):
            proof_manifest.validate_declared_currentness(mismatched)

    def test_partial_registry_or_mixed_domain_state_is_a_manifest_error(self) -> None:
        partial = _verified_manifest()
        source = stable_pending_receipt()["source"]
        partial["release_publications"][
            crates_contract.CRATES_IO_PUBLICATION_KEY
        ] = _rebind_crates(
            crates_receipt(9), source, partial["rust_publish"]
        )
        mixed = _pending_manifest()
        mixed["release_publications"][
            apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
        ] = stable_verified_receipt()
        for label, manifest in (("partial", partial), ("mixed", mixed)):
            with self.subTest(label=label), self.assertRaises(
                proof_manifest.ProofManifestError
            ):
                proof_manifest.validate_declared_currentness(manifest)


if __name__ == "__main__":
    unittest.main()
