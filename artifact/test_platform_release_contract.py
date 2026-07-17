#!/usr/bin/env python3
"""Fail-closed tests for the captured ABI2 platform publication receipt."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import android_device_proof
import c_abi_contract
import platform_distribution
import platform_release_contract as contract


ROOT = pathlib.Path(__file__).resolve().parents[1]


class PlatformReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        manifest = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        self.receipt = manifest["release_publications"]["platform_r2"]

    def validate(self, receipt: object) -> None:
        contract.validate_release_publications(
            {"release_publications": {"platform_r2": receipt}}
        )

    def pending_receipt(self) -> dict[str, object]:
        receipt = copy.deepcopy(self.receipt)
        receipt["status"] = contract.PLATFORM_RELEASE_STATUS_PENDING
        observation = receipt["observation"]
        observation["fresh_download_verified"] = False
        observation["deep_distribution_verified"] = False
        observation["release_asset_verification_count"] = 0
        observation["candidate_attestation"]["verified"] = False
        observation["candidate_attestation"]["subjects"] = []
        observation["release_attestation"]["verified"] = False
        observation["release_attestation"]["subjects"] = []
        observation["release_attestation"]["verification_record_sha256"] = None
        return receipt

    def test_repository_receipt_is_exact_verified_contract(self) -> None:
        self.validate(self.receipt)

    def test_pending_state_is_atomic_and_explicit(self) -> None:
        receipt = self.pending_receipt()
        self.validate(receipt)

        for path, value in (
            (("observation", "fresh_download_verified"), True),
            (("observation", "deep_distribution_verified"), True),
            (("observation", "release_asset_verification_count"), 1),
            (("observation", "candidate_attestation", "verified"), True),
            (("observation", "release_attestation", "verified"), True),
        ):
            with self.subTest(path=path):
                mutated = copy.deepcopy(receipt)
                target = mutated
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(contract.PlatformReleaseContractError):
                    self.validate(mutated)

    def test_unknown_states_and_keys_fail_closed(self) -> None:
        for mutation in ("status", "receipt_key", "observation_key"):
            with self.subTest(mutation=mutation):
                receipt = copy.deepcopy(self.receipt)
                if mutation == "status":
                    receipt["status"] = "verified_typo"
                    manifest = {"release_publications": {"platform_r2": receipt}}
                elif mutation == "receipt_key":
                    receipt["unexpected"] = True
                    manifest = {"release_publications": {"platform_r2": receipt}}
                else:
                    receipt["observation"]["unexpected"] = True
                    manifest = {"release_publications": {"platform_r2": receipt}}
                with self.assertRaises(contract.PlatformReleaseContractError):
                    contract.validate_release_publications(manifest)

        with self.assertRaisesRegex(
            contract.PlatformReleaseContractError, "unknown entries"
        ):
            contract.validate_release_publications(
                {"release_publications": {"platform_r3": {}}}
            )

    def test_json_numeric_fields_reject_boolean_aliases(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["schema_version"] = True
        with self.assertRaisesRegex(
            contract.PlatformReleaseContractError, "receipt schema differs"
        ):
            self.validate(receipt)

        receipt = self.pending_receipt()
        receipt["observation"]["release_asset_verification_count"] = False
        with self.assertRaisesRegex(
            contract.PlatformReleaseContractError, "partially promoted"
        ):
            self.validate(receipt)

    def test_public_asset_set_is_exact_ordered_and_unique(self) -> None:
        for mutation in ("missing", "extra", "duplicate", "hash", "size", "order"):
            with self.subTest(mutation=mutation):
                receipt = copy.deepcopy(self.receipt)
                assets = receipt["observation"]["assets"]
                if mutation == "missing":
                    assets.pop()
                elif mutation == "extra":
                    assets.append(
                        {"bytes": 1, "name": "unexpected.bin", "sha256": "0" * 64}
                    )
                elif mutation == "duplicate":
                    assets[-1] = copy.deepcopy(assets[0])
                elif mutation == "hash":
                    assets[0]["sha256"] = "0" * 64
                elif mutation == "size":
                    assets[0]["bytes"] += 1
                else:
                    assets[0], assets[1] = assets[1], assets[0]
                with self.assertRaisesRegex(
                    contract.PlatformReleaseContractError, "asset set differs"
                ):
                    self.validate(receipt)

    def test_source_identity_and_historical_digest_are_pinned(self) -> None:
        source = self.receipt["observation"]["source"]
        self.assertEqual(
            contract.CANONICAL_SOURCE_TREE_SHA256,
            source["canonical_source_tree_sha256"],
        )
        for field in (
            "tag_object",
            "tag_commit",
            "tag_tree",
            "verifier_commit",
            "canonical_source_tree_sha256",
        ):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt["observation"]["source"][field] = "0" * len(source[field])
                with self.assertRaisesRegex(
                    contract.PlatformReleaseContractError, "source identity differs"
                ):
                    self.validate(receipt)

    def test_attestation_subject_sets_are_exact_not_counts(self) -> None:
        for attestation in ("candidate_attestation", "release_attestation"):
            for mutation in ("missing", "extra", "duplicate", "digest"):
                with self.subTest(attestation=attestation, mutation=mutation):
                    receipt = copy.deepcopy(self.receipt)
                    subjects = receipt["observation"][attestation]["subjects"]
                    if mutation == "missing":
                        subjects.pop()
                    elif mutation == "extra":
                        subjects.append(
                            {"digest": {"sha256": "0" * 64}, "name": "extra"}
                        )
                    elif mutation == "duplicate":
                        subjects[-1] = copy.deepcopy(subjects[0])
                    else:
                        subjects[-1]["digest"] = {"sha256": "0" * 64}
                    with self.assertRaisesRegex(
                        contract.PlatformReleaseContractError, "subjects differ"
                    ):
                        self.validate(receipt)

    def test_android_runtime_claim_cannot_drift_or_promote_to_physical(self) -> None:
        for field, value in (
            ("device_kind", "physical"),
            ("device_abi", "x86_64"),
            ("device_sdk", 34),
            ("page_size", 4096),
            ("proof_schema", 2),
            ("proof_sha256", "0" * 64),
            ("tested_aar_sha256", "0" * 64),
        ):
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt["observation"]["android_runtime_evidence"][field] = value
                with self.assertRaisesRegex(
                    contract.PlatformReleaseContractError,
                    "Android runtime evidence differs",
                ):
                    self.validate(receipt)

    def test_windows_and_registry_boundaries_cannot_be_overclaimed(self) -> None:
        receipt = copy.deepcopy(self.receipt)
        receipt["observation"]["windows_distribution"] = {
            "authenticode_signed": True,
            "release_class": "signed_release",
        }
        with self.assertRaisesRegex(
            contract.PlatformReleaseContractError, "Windows signing boundary differs"
        ):
            self.validate(receipt)

        for registry in contract.REGISTRY_STATES:
            with self.subTest(registry=registry):
                receipt = copy.deepcopy(self.receipt)
                receipt["observation"]["registries"][registry] = "published"
                with self.assertRaisesRegex(
                    contract.PlatformReleaseContractError,
                    "registry publication state differs",
                ):
                    self.validate(receipt)

    def test_observation_timestamp_is_strict_and_not_before_publication(self) -> None:
        for value in ("2026-07-17 05:01:55Z", "2026-07-17T04:49:04Z"):
            with self.subTest(value=value):
                receipt = copy.deepcopy(self.receipt)
                receipt["observation"]["observed_at"] = value
                with self.assertRaises(contract.PlatformReleaseContractError):
                    self.validate(receipt)

    def test_schema_and_distribution_constants_cannot_drift(self) -> None:
        self.assertEqual(
            contract.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            android_device_proof.PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            contract.PLATFORM_DISTRIBUTION_SCHEMA_VERSION,
            platform_distribution.SCHEMA_VERSION,
        )
        self.assertEqual(contract.PLATFORM_DISTRIBUTION_KIND, platform_distribution.KIND)
        self.assertEqual(contract.PRODUCT_VERSION, platform_distribution.PRODUCT_VERSION)
        self.assertEqual(contract.PRODUCT_VERSION, c_abi_contract.PACKAGE_SEMVER)
        self.assertEqual(contract.RELEASE_TAG, platform_distribution.RELEASE_TAG)
        self.assertEqual(contract.PLATFORM_INPUT_ASSETS, platform_distribution.INPUT_ASSETS)
        self.assertEqual(contract.PLATFORM_RELEASE_FILES, platform_distribution.RELEASE_FILES)

    def test_absent_optional_publication_receipts_remain_valid(self) -> None:
        contract.validate_release_publications({})
        contract.validate_release_publications({"release_publications": {}})


if __name__ == "__main__":
    unittest.main()
