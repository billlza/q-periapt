#!/usr/bin/env python3
"""Fail-closed tests for the coordinated stable publication cohort."""

from __future__ import annotations

import copy
import json
import pathlib
import unittest

import apple_publication_contract as apple_contract
import apple_stable_publication as apple_producer
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
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


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _rebind_platform(
    receipt: dict[str, object], source: dict[str, str]
) -> dict[str, object]:
    rebound = copy.deepcopy(receipt)
    observation = rebound["observation"]
    platform_source = observation["source"]
    platform_source.update(source)
    platform_source["tag_object"] = "9" * 40
    platform_source["verifier_commit"] = source["tag_commit"]
    candidate = observation["candidate_attestation"]
    candidate["source_digest"] = source["tag_commit"]
    security_gate = candidate["security_gate"]
    security_gate["source_parent_commit"] = source["source_parent_commit"]
    security_gate["tag_commit"] = source["tag_commit"]
    for workflow in security_gate["workflows"].values():
        workflow["head_sha"] = source["tag_commit"]
    if rebound["status"] == "observed_public_immutable_fresh_download_verified":
        observation["fresh_download_verification"]["verifier_commit"] = source[
            "tag_commit"
        ]
        observation["release_attestation"]["subjects"][0]["digest"]["sha1"] = (
            platform_source["tag_object"]
        )
    return rebound


def _rebind_crates(
    receipt: dict[str, object],
    source: dict[str, str],
    rust_publish: dict[str, object],
) -> dict[str, object]:
    rebound = copy.deepcopy(receipt)
    observation = rebound["observation"]
    observation["source"] = {
        key: source[key]
        for key in (
            "canonical_source_tree_sha256",
            "source_parent_commit",
            "tag_commit",
            "tag_tree",
        )
    }
    package_contract = observation["package_contract"]
    package_contract["source_commit"] = source["source_parent_commit"]
    package_contract["completed_at"] = rust_publish["completed_at"]
    package_contract["transcript_sha256"] = rust_publish[
        "transcript_sha256"
    ]
    package_contract["handoff_sha256"] = rust_publish[
        "handoff_manifest_sha256"
    ]
    return rebound


def rebind_rust_publish_source(
    section: dict[str, object],
    *,
    source_commit: str,
    source_digest: str,
) -> dict[str, object]:
    """Rebind a complete current Rust fixture to one synthetic source root."""

    import proof_manifest

    rebound = copy.deepcopy(section)
    previous_commit = rebound["source_commit"]
    previous_digest = rebound["proof_source_tree_sha256"]
    status = rebound["current_local_status"]
    if (
        not isinstance(previous_commit, str)
        or not isinstance(previous_digest, str)
        or not isinstance(status, str)
        or status.count(previous_commit) != 1
        or status.count(previous_digest) != 1
    ):
        raise AssertionError("Rust package fixture source binding is malformed")
    rebound["source_commit"] = source_commit
    rebound["proof_source_tree_sha256"] = source_digest
    transaction = f"transaction.1-{'7' * 32}"
    rebound["boundary"] = proof_manifest.RUST_PACKAGE_BOUNDARY
    rebound["evidence_schema"] = 2
    rebound["handoff_manifest_path"] = (
        "target/qperiapt-rust-package-handoffs/"
        f"{transaction}/rust-package-handoff.json"
    )
    rebound["handoff_manifest_sha256"] = "6" * 64
    rebound["transcript_path"] = (
        "target/qperiapt-rust-package-handoffs/"
        f"{transaction}/rust-package-contract.log"
    )
    rebound["current_local_status"] = (
        proof_manifest.rust_package_current_local_status(
            source_commit=source_commit,
            source_digest=source_digest,
            completed_at=rebound["completed_at"],
            advisory_commit=rebound["advisory_db_commit"],
            registry_package_count=rebound[
                "crates_io_registry_package_count"
            ],
            normalized_lock_sha256=rebound[
                "normalized_cargo_lock_sha256"
            ],
        )
    )
    return rebound


def rebind_stable_current_source(
    manifest: dict[str, object],
    *,
    source_commit: str,
    source_digest: str,
) -> None:
    """Install complete synthetic physical/performance source projections."""

    import proof_manifest

    manifest["android_aar"] = {
        "aar_path": proof_manifest.ANDROID_AAR_PATH,
        "aar_sha256": "1" * 64,
        "current_source_status": "current_clean_tree_package_pass",
        "manifest_generated_at": "2026-08-15T00:00:00Z",
        "manifest_path": proof_manifest.ANDROID_AAR_MANIFEST_PATH,
        "manifest_schema": 4,
        "manifest_sha256": "2" * 64,
        "proof_source_tree_sha256": source_digest,
        "source_commit": source_commit,
        "source_tree_dirty": False,
        "status": "pass",
        "targets": list(proof_manifest.ANDROID_ABIS),
    }
    physical_run = "3" * 32
    manifest["android_physical_runtime"] = {
        "android_sdk": 36,
        "build_tools": proof_manifest.ANDROID_RELEASE_BUILD_TOOLS,
        "covered_tests": list(proof_manifest.ANDROID_EXPECTED_TESTS),
        "current_source_status": "current_clean_tree_physical_pass",
        "device_abi": proof_manifest.ANDROID_RELEASE_ABI,
        "device_kind": "physical",
        "page_size": 4_096,
        "proof_generated_at": "2026-08-15T00:01:00Z",
        "proof_path": (
            "target/qperiapt-android-device-smoke-runs/"
            f"{physical_run}/proof/qperiapt-android-device-proof.json"
        ),
        "proof_schema": proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "proof_sha256": "4" * 64,
        "proof_source_tree_sha256": source_digest,
        "release_candidate_mode": True,
        "run_id": physical_run,
        "source_commit": source_commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    manifest["performance"] = {
        "current_source_status": "current_controlled_pass",
        "proof_generated_at": "2026-08-15T00:02:00Z",
        "proof_path": "target/performance/paired-proof.json",
        "proof_schema": proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
        "proof_sha256": "5" * 64,
        "proof_source_tree_sha256": source_digest,
        "source_commit": source_commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    apple = manifest.get("apple_device")
    if isinstance(apple, dict):
        apple["proof_source_tree_sha256"] = source_digest


def source_manifest_fixture(
    legacy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the exact post-migration source-results publication state."""

    if legacy is None:
        legacy = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
    manifest = copy.deepcopy(legacy)
    apple_pending = stable_pending_receipt()
    source = apple_pending["source"]
    manifest["provenance"]["snapshot_commit"] = source[
        "source_parent_commit"
    ]
    manifest["proof_source_tree_sha256"] = source[
        "canonical_source_tree_sha256"
    ]
    manifest["rust_publish"] = rebind_rust_publish_source(
        manifest["rust_publish"],
        source_commit=source["source_parent_commit"],
        source_digest=source["canonical_source_tree_sha256"],
    )
    rebind_stable_current_source(
        manifest,
        source_commit=source["source_parent_commit"],
        source_digest=source["canonical_source_tree_sha256"],
    )
    manifest["swift_xcframework"] = contract.neutral_swift_selector(manifest)
    return manifest


def pending_manifest_fixture(
    legacy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the coordinated Apple/platform pending publication state."""

    manifest = source_manifest_fixture(legacy)
    apple = stable_pending_receipt()
    source = apple["source"]
    platform = _rebind_platform(platform_pending_receipt(), source)
    manifest["release_publications"][
        apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
    ] = apple
    manifest["release_publications"][
        platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY
    ] = platform
    return manifest


def verified_manifest_fixture(
    legacy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the fully verified cohort with the stable Apple selector active."""

    manifest = pending_manifest_fixture(legacy)
    apple = stable_verified_receipt()
    source = apple["source"]
    platform = _rebind_platform(platform_verified_receipt(), source)
    registry = _rebind_crates(
        crates_receipt(10), source, manifest["rust_publish"]
    )
    publications = manifest["release_publications"]
    publications[apple_contract.APPLE_V0_1_0_PUBLICATION_KEY] = apple
    publications[platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY] = platform
    publications[crates_contract.CRATES_IO_PUBLICATION_KEY] = registry
    swift = manifest["swift_xcframework"]
    swift["active_publication_key"] = (
        apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
    )
    swift["distribution"] = copy.deepcopy(apple["distribution"])
    return manifest


class ReleasePublicationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.legacy = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )

    def source_manifest(self) -> dict[str, object]:
        return source_manifest_fixture(self.legacy)

    def pending_manifest(self) -> dict[str, object]:
        return pending_manifest_fixture(self.legacy)

    def verified_manifest(self) -> dict[str, object]:
        return verified_manifest_fixture(self.legacy)

    def test_exact_source_pending_and_verified_states_pass(self) -> None:
        source = self.source_manifest()
        pending = self.pending_manifest()
        verified = self.verified_manifest()
        for expected_state, manifest in (
            (contract.PUBLICATION_STATE_SOURCE, source),
            (contract.PUBLICATION_STATE_PENDING, pending),
            (contract.PUBLICATION_STATE_VERIFIED, verified),
        ):
            with self.subTest(expected_state=expected_state):
                contract.validate_release_publications(manifest)
                contract.validate_stable_source_currentness(manifest)
                self.assertEqual(expected_state, contract.publication_state(manifest))
        contract.validate_release_publication_transition(source, pending)
        contract.validate_release_publication_transition(pending, verified)

    def test_pending_and_verified_reject_forged_stale_source_gates(self) -> None:
        mutations = (
            (
                "physical status",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current clean physical",
            ),
            (
                "physical ABI",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "device_abi", "x86_64"
                ),
                "arm64-v8a release mode",
            ),
            (
                "physical release mode",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "release_candidate_mode", False
                ),
                "arm64-v8a release mode",
            ),
            (
                "physical proof schema",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "proof_schema", 5
                ),
                "arm64-v8a release mode",
            ),
            (
                "physical source",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "proof_source_tree_sha256", "f" * 64
                ),
                "current clean physical",
            ),
            (
                "AAR status",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current clean Android AAR",
            ),
            (
                "AAR source commit",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "source_commit", "f" * 40
                ),
                "current clean Android AAR",
            ),
            (
                "AAR source digest",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "proof_source_tree_sha256", "f" * 64
                ),
                "current clean Android AAR",
            ),
            (
                "AAR dirty source",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "source_tree_dirty", True
                ),
                "current clean Android AAR",
            ),
            (
                "AAR manifest schema",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "manifest_schema", 3
                ),
                "current clean Android AAR",
            ),
            (
                "AAR canonical path",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "aar_path", "target/forged.aar"
                ),
                "current clean Android AAR",
            ),
            (
                "AAR manifest hash",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "manifest_sha256", "bad"
                ),
                "current clean Android AAR",
            ),
            (
                "physical ABI absent from AAR",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "targets", ["x86_64"]
                ),
                "current clean Android AAR|covered by the selected AAR",
            ),
            (
                "performance status",
                lambda manifest: manifest["performance"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current controlled performance",
            ),
            (
                "performance proof schema",
                lambda manifest: manifest["performance"].__setitem__(
                    "proof_schema", 5
                ),
                "current controlled performance",
            ),
            (
                "performance source commit",
                lambda manifest: manifest["performance"].__setitem__(
                    "source_commit", "f" * 40
                ),
                "current controlled performance",
            ),
            (
                "performance dirty source",
                lambda manifest: manifest["performance"].__setitem__(
                    "source_tree_dirty", True
                ),
                "current controlled performance",
            ),
            (
                "performance proof path",
                lambda manifest: manifest["performance"].__setitem__(
                    "proof_path", "../forged.json"
                ),
                "current controlled performance",
            ),
            (
                "performance proof hash",
                lambda manifest: manifest["performance"].__setitem__(
                    "proof_sha256", "bad"
                ),
                "current controlled performance",
            ),
            (
                "physical run identity",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "run_id", "bad"
                ),
                "proof identity is malformed",
            ),
            (
                "physical proof path",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "proof_path", "target/forged.json"
                ),
                "proof identity is malformed",
            ),
            (
                "physical proof hash",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "proof_sha256", "bad"
                ),
                "proof identity is malformed",
            ),
            (
                "physical covered tests",
                lambda manifest: manifest["android_physical_runtime"].__setitem__(
                    "covered_tests", []
                ),
                "arm64-v8a release mode",
            ),
            (
                "performance source",
                lambda manifest: manifest["performance"].__setitem__(
                    "proof_source_tree_sha256", "f" * 64
                ),
                "current controlled performance",
            ),
        )
        for state_factory in (self.pending_manifest, self.verified_manifest):
            for label, mutate, message in mutations:
                with self.subTest(state=state_factory.__name__, mutation=label):
                    invalid = state_factory()
                    mutate(invalid)
                    with self.assertRaisesRegex(
                        contract.ReleasePublicationContractError,
                        message,
                    ):
                        contract.validate_release_publications(invalid)

    def test_stable_source_currentness_is_a_standalone_manifest_authority(
        self,
    ) -> None:
        manifest = self.pending_manifest()
        contract.validate_stable_source_currentness(manifest)
        for label, section, field, value in (
            (
                "physical path",
                "android_physical_runtime",
                "proof_path",
                "target/forged.json",
            ),
            (
                "performance source",
                "performance",
                "source_commit",
                "f" * 40,
            ),
            (
                "performance path",
                "performance",
                "proof_path",
                "target/performance/nested/forged.json",
            ),
        ):
            with self.subTest(label=label):
                invalid = copy.deepcopy(manifest)
                invalid[section][field] = value
                with self.assertRaises(
                    contract.ReleasePublicationContractError
                ):
                    contract.validate_stable_source_currentness(invalid)

    def test_one_time_selector_migration_is_exact(self) -> None:
        migrated = contract.neutral_swift_selector(self.legacy)
        self.assertEqual(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            migrated["active_publication_key"],
        )
        self.assertEqual(contract.NEUTRAL_SWIFT_BOUNDARY, migrated["boundary"])
        source = self.source_manifest()
        contract.validate_release_publication_transition(self.legacy, source)

        changed = copy.deepcopy(self.legacy)
        changed["swift_xcframework"]["distribution"]["artifact_size"] += 1
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "exact legacy"
        ):
            contract.neutral_swift_selector(changed)

    def test_pending_requires_both_domains_and_never_changes_selector(self) -> None:
        source = self.source_manifest()
        pending = self.pending_manifest()
        for missing in (
            apple_contract.APPLE_V0_1_0_PUBLICATION_KEY,
            platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY,
        ):
            with self.subTest(missing=missing):
                invalid = copy.deepcopy(pending)
                invalid["release_publications"].pop(missing)
                with self.assertRaisesRegex(
                    contract.ReleasePublicationContractError,
                    "coordinated cohort",
                ):
                    contract.validate_release_publications(invalid)

        activated = copy.deepcopy(pending)
        activated["swift_xcframework"]["active_publication_key"] = (
            apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
        )
        activated["swift_xcframework"]["distribution"] = copy.deepcopy(
            activated["release_publications"][
                apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
            ]["distribution"]
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "must be verified"
        ):
            contract.validate_release_publications(activated)

        unchanged_selector = copy.deepcopy(source["swift_xcframework"])
        contract.validate_release_publication_transition(source, pending)
        self.assertEqual(unchanged_selector, pending["swift_xcframework"])

    def test_apple_promotion_reads_pending_leaf_without_activating_selector(self) -> None:
        pending = self.pending_manifest()
        contract.validate_release_publications(pending)
        leaf = apple_producer._pending_leaf_from_results(pending)
        self.assertEqual(
            pending["release_publications"][
                apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
            ],
            leaf,
        )
        self.assertEqual(
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            pending["swift_xcframework"]["active_publication_key"],
        )
        self.assertNotEqual(
            pending["swift_xcframework"]["distribution"],
            leaf["distribution"],
        )

    def test_verified_requires_all_ten_crates_and_atomic_selector_switch(self) -> None:
        pending = self.pending_manifest()
        verified = self.verified_manifest()
        missing_registry = copy.deepcopy(verified)
        missing_registry["release_publications"].pop(
            crates_contract.CRATES_IO_PUBLICATION_KEY
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "coordinated cohort"
        ):
            contract.validate_release_publications(missing_registry)

        partial = copy.deepcopy(verified)
        source = stable_pending_receipt()["source"]
        partial["release_publications"][
            crates_contract.CRATES_IO_PUBLICATION_KEY
        ] = _rebind_crates(
            crates_receipt(9), source, partial["rust_publish"]
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "coordinated cohort"
        ):
            contract.validate_release_publications(partial)

        stale_selector = copy.deepcopy(verified)
        stale_selector["swift_xcframework"] = copy.deepcopy(
            pending["swift_xcframework"]
        )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "coordinated cohort state",
        ):
            contract.validate_release_publications(stale_selector)

        contract.validate_release_publication_transition(pending, verified)

    def test_direct_source_to_verified_and_mixed_statuses_are_rejected(self) -> None:
        source = self.source_manifest()
        verified = self.verified_manifest()
        with self.assertRaises(contract.ReleasePublicationContractError):
            contract.validate_release_publication_transition(source, verified)

        mixed = self.pending_manifest()
        mixed["release_publications"][
            apple_contract.APPLE_V0_1_0_PUBLICATION_KEY
        ] = stable_verified_receipt()
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "coordinated cohort"
        ):
            contract.validate_release_publications(mixed)

    def test_every_cross_domain_source_field_is_bound_to_results(self) -> None:
        for field, replacement in (
            ("source_parent_commit", "a" * 40),
            ("tag_commit", "b" * 40),
            ("tag_tree", "c" * 40),
            ("canonical_source_tree_sha256", "d" * 64),
        ):
            with self.subTest(field=field):
                invalid = self.pending_manifest()
                platform = invalid["release_publications"][
                    platform_contract.PLATFORM_V0_1_0_PUBLICATION_KEY
                ]
                platform["observation"]["source"][field] = replacement
                if field == "tag_commit":
                    platform["observation"]["source"]["verifier_commit"] = replacement
                    platform["observation"]["candidate_attestation"][
                        "source_digest"
                    ] = replacement
                with self.assertRaises(contract.ReleasePublicationContractError):
                    contract.validate_release_publications(invalid)

        wrong_manifest = self.pending_manifest()
        wrong_manifest["proof_source_tree_sha256"] = "e" * 64
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "manifest root"
        ):
            contract.validate_release_publications(wrong_manifest)

    def test_registry_receipt_binds_selected_rust_package_evidence(self) -> None:
        for field, replacement, pattern in (
            ("source_commit", "a" * 40, "source"),
            ("completed_at", "2026-08-15T00:00:00Z", "completed_at"),
            ("transcript_sha256", "b" * 64, "transcript_sha256"),
            ("handoff_sha256", "c" * 64, "handoff_sha256"),
        ):
            with self.subTest(field=field):
                invalid = self.verified_manifest()
                registry = invalid["release_publications"][
                    crates_contract.CRATES_IO_PUBLICATION_KEY
                ]
                registry["observation"]["package_contract"][field] = replacement
                with self.assertRaisesRegex(
                    contract.ReleasePublicationContractError,
                    pattern,
                ):
                    contract.validate_release_publications(invalid)

    def test_historical_receipts_are_immutable_and_unknown_keys_fail(self) -> None:
        pending = self.pending_manifest()
        for key in (
            apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            platform_contract.PLATFORM_R2_PUBLICATION_KEY,
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(pending)
                changed["release_publications"][key]["boundary"] += " changed"
                with self.assertRaises(contract.ReleasePublicationContractError):
                    contract.validate_release_publication_transition(pending, changed)

        unknown = self.source_manifest()
        unknown["release_publications"]["future_publication"] = {}
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "unknown entries"
        ):
            contract.validate_release_publications(unknown)


if __name__ == "__main__":
    unittest.main()
