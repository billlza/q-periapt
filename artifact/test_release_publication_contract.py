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
    alpha2_receipt,
    stable_pending_receipt,
    stable_verified_receipt,
)
from test_crates_io_publication_contract import receipt_fixture as crates_receipt
from test_platform_stable_publication_contract import (
    pending_receipt as platform_pending_receipt,
    verified_receipt as platform_verified_receipt,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]


"""Frozen alpha.2 legacy selector fields.

These are the exact pre-migration values of the five fields the retired
one-time neutral selector migration used to rewrite. The migration
completed on the published 0.1.3 line and its machinery is deleted, so
these bytes are pinned here purely as frozen history: the regression
tests reconstruct the retired legacy selector shape from them and prove
the restructured contract now fails it closed.
"""
LEGACY_ALPHA2_SWIFT_FIELDS: dict[str, str] = {
    "boundary": (
        "This is the public immutable Developer ID-signed Apple-only static"
        " XCFramework prerelease for SwiftPM binaryTarget consumption. GitHub"
        " release attestation and the exact four public asset digests have"
        " been verified, and a fresh remote URL consumer verification ran"
        " against the committed publication state recorded below. The static"
        " SDK payload has no standalone executable or notarizable bundle, so"
        " SDK notarization and stapling are not applicable; the final"
        " consuming macOS app still requires its own signing and"
        " notarization, and the final iOS app requires signing and"
        " provisioning."
    ),
    "command": (
        "QPERIAPT_APPLE_RELEASE_CONFIRM=v0.1.0-alpha.2-r1"
        " QPERIAPT_APPLE_RELEASE_SOURCE_COMMIT="
        "5664fd86a617f92b620ea37e7692d3417d0e307d"
        " sh artifact/swift-xcframework-release.sh"
    ),
    "current_local_status": (
        "The 2026-07-17 public immutable r1 prerelease was built from source"
        " commit 5664fd86a617f92b620ea37e7692d3417d0e307d with Rust 1.96.1,"
        " Cargo 1.96.1, Xcode 26.6, and Swift 6.3.3. All five Apple Rust"
        " targets, exact nine-symbol ABI2 exports, schema-3 distribution"
        " identity, schema-5 manifest toolchain identity, static-archive path"
        " hygiene, strict Developer ID signature, deterministic ZIP, three"
        " isolated SwiftPM product tests, macOS universal link/runtime, and"
        " iOS device/simulator links passed. The exact four published assets"
        " match the pinned hashes, GitHub reports the release immutable, and"
        " its release attestation verifies. A fresh remote URL consumer at"
        " verifier commit d93a7cab2e00ce1036f6b218eef01bb889cb60a9"
        " redownloaded and reverified all four assets, executed exactly three"
        " passing XCTest cases, and passed macOS universal plus iOS"
        " device/simulator link checks."
    ),
    "current_source_status": "public_immutable_remote_consumer_verified",
    "mode": "Developer ID-signed SwiftPM binaryTarget release candidate",
}


_STABLE_COHORT_PUBLICATION_KEYS = (
    apple_contract.APPLE_V0_1_4_PUBLICATION_KEY,
    platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY,
    crates_contract.CRATES_IO_PUBLICATION_KEY,
)
# The published 0.1.3 line's frozen leaves are permanent history in every
# live manifest on and after the 0.1.4 opening; together with the frozen
# prerelease leaves they form the five-leaf historical floor.
_FROZEN_STABLE_PUBLICATION_KEYS = (
    apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
    platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
    crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
)
_FROZEN_HISTORICAL_PUBLICATION_KEYS = (
    apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
    platform_contract.PLATFORM_R2_PUBLICATION_KEY,
    *_FROZEN_STABLE_PUBLICATION_KEYS,
)


def _drop_active_cohort_leaves(manifest: dict[str, object]) -> None:
    publications = manifest.get("release_publications")
    if isinstance(publications, dict):
        for key in _STABLE_COHORT_PUBLICATION_KEYS:
            publications.pop(key, None)


def legacy_swift_manifest_fixture(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Return a manifest carrying the exact retired legacy alpha.2 selector.

    The frozen legacy baseline predates both the published v0.1.3 line and
    the active v0.1.4 cohort, so the reconstruction drops every stable
    cohort leaf and restores the frozen alpha.2 distribution alongside the
    pinned legacy selector fields. The restructured contract must reject
    this shape: its one-time migration completed on the 0.1.3 line and
    was retired with the alpha.2 selector machinery.
    """

    legacy = copy.deepcopy(manifest)
    publications = legacy.get("release_publications")
    if isinstance(publications, dict):
        for key in (
            *_STABLE_COHORT_PUBLICATION_KEYS,
            *_FROZEN_STABLE_PUBLICATION_KEYS,
        ):
            publications.pop(key, None)
    swift = legacy["swift_xcframework"]
    assert isinstance(swift, dict)
    swift.pop("active_publication_key", None)
    swift["distribution"] = apple_contract.frozen_alpha2_r1_distribution()
    swift.update(copy.deepcopy(LEGACY_ALPHA2_SWIFT_FIELDS))
    return legacy


def frozen_v0_1_3_selector_fixture(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Return the source-state Apple selector for any live manifest state.

    Since the 0.1.3 line published, every pre-verification manifest keeps
    the neutral selector fields with the frozen published apple_v0_1_3
    receipt active; a verified v0.1.4 cohort switches only the active key
    and distribution, so this rebuilds the exact source-state selector
    regardless of which cohort state is installed.
    """

    swift = copy.deepcopy(manifest["swift_xcframework"])
    assert isinstance(swift, dict)
    swift.update(
        {
            "active_publication_key": (
                apple_contract.APPLE_V0_1_3_PUBLICATION_KEY
            ),
            "boundary": contract.NEUTRAL_SWIFT_BOUNDARY,
            "command": contract.NEUTRAL_SWIFT_COMMAND,
            "current_local_status": contract.NEUTRAL_SWIFT_LOCAL_STATUS,
            "current_source_status": contract.NEUTRAL_SWIFT_SOURCE_STATUS,
            "distribution": apple_contract.frozen_v0_1_3_distribution(),
            "mode": contract.NEUTRAL_SWIFT_MODE,
        }
    )
    return swift


def source_baseline_fixture(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Return the live manifest reduced to its source-results baseline.

    The live manifest permanently carries the five frozen historical
    leaves and may additionally carry an active v0.1.4 cohort state.  The
    synthetic fixtures rebuild the active cohort from explicit receipts,
    so the baseline drops only the v0.1.4 leaves and restores the
    source-state selector: active on the frozen published apple_v0_1_3
    receipt.
    """

    baseline = copy.deepcopy(manifest)
    _drop_active_cohort_leaves(baseline)
    baseline["swift_xcframework"] = frozen_v0_1_3_selector_fixture(manifest)
    return baseline


def frozen_apple_v0_1_3_receipt() -> dict[str, object]:
    """Assemble the frozen published apple_v0_1_3 receipt from contract bytes."""

    return {
        "boundary": apple_contract.APPLE_V0_1_3_BOUNDARY,
        "distribution": apple_contract.frozen_v0_1_3_distribution(),
        "identity": dict(apple_contract.APPLE_V0_1_3_IDENTITY),
        "kind": apple_contract.APPLE_PUBLICATION_KIND,
        "publication": apple_contract.frozen_v0_1_3_publication(),
        "schema_version": apple_contract.APPLE_PUBLICATION_SCHEMA_VERSION,
        "source": apple_contract.frozen_v0_1_3_source(),
        "status": apple_contract.APPLE_STATUS_VERIFIED,
    }


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
    code_scanning = security_gate["code_scanning"]
    code_scanning["main_ref"]["commit_sha"] = source["tag_commit"]
    for analysis in code_scanning["analyses"]:
        analysis["commit_sha"] = source["tag_commit"]
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
    completed_at = rust_publish["completed_at"]
    package_contract["completed_at"] = completed_at
    package_contract["transcript_sha256"] = rust_publish[
        "transcript_sha256"
    ]
    package_contract["handoff_sha256"] = rust_publish[
        "handoff_manifest_sha256"
    ]
    # Keep the observation chain consistent with the selected Rust evidence:
    # the contract requires completed_at <= verified_at <= observed_at.
    if str(observation["observed_at"]) < str(completed_at):
        observation["observed_at"] = completed_at
    for crate in rebound["crates"]:
        verified_at = crate.get("verified_at")
        if verified_at is not None and str(verified_at) < str(completed_at):
            crate["verified_at"] = completed_at
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
    """Install the synthetic package evidence required for stable publication."""

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
    android_run = "3" * 32
    android_proof_sha256 = "4" * 64
    manifest["android_device_runtime"] = {
        "android_sdk": proof_manifest.ANDROID_RELEASE_SDK,
        "build_tools": proof_manifest.ANDROID_RELEASE_BUILD_TOOLS,
        "covered_tests": list(proof_manifest.ANDROID_EXPECTED_TESTS),
        "current_source_status": "current_clean_tree_emulator_pass",
        "device_abi": proof_manifest.ANDROID_RELEASE_ABI,
        "device_kind": "emulator",
        "page_size": proof_manifest.ANDROID_RELEASE_PAGE_SIZE,
        "proof_generated_at": "2026-08-15T00:01:00Z",
        "proof_path": (
            "target/qperiapt-android-device-smoke-runs/"
            f"{android_run}/proof/qperiapt-android-device-proof.json"
        ),
        "proof_schema": proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
        "proof_sha256": android_proof_sha256,
        "proof_source_tree_sha256": source_digest,
        "release_candidate_mode": True,
        "run_id": android_run,
        "source_commit": source_commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    consumer_run = "4" * 32
    manifest["local_release_index"] = {
        "android_runtime_proof_sha256": android_proof_sha256,
        "android_runtime_run_id": android_run,
        "channel": "release",
        "consumer_receipt_generated_at": "2026-08-15T00:03:00Z",
        "consumer_receipt_path": (
            "target/qperiapt-release-consumer-smoke/receipts/"
            f"{consumer_run}/qperiapt-release-consumer-receipt.json"
        ),
        "consumer_receipt_run_id": consumer_run,
        "consumer_receipt_schema": (
            proof_manifest.LOCAL_RELEASE_CONSUMER_RECEIPT_SCHEMA_VERSION
        ),
        "consumer_receipt_sha256": "5" * 64,
        "consumer_status": "pass",
        "current_source_status": "current_clean_tree_local_index_consumer_pass",
        "generated_at": "2026-08-15T00:02:00Z",
        "index_path": (
            "target/qperiapt-local-release/release/0.1.4/"
            f"{source_commit}/index.json"
        ),
        "index_schema": proof_manifest.LOCAL_RELEASE_INDEX_SCHEMA_VERSION,
        "index_sha256": "6" * 64,
        "proof_source_tree_sha256": source_digest,
        "source_commit": source_commit,
        "source_tree_dirty": False,
        "status": "pass",
    }
    manifest.pop("android_physical_runtime", None)
    performance = manifest.get("performance")
    if isinstance(performance, dict):
        performance["current_source_status"] = "stale_requires_rerun"
    apple = manifest.get("apple_device")
    if isinstance(apple, dict):
        apple["current_source_status"] = "stale_requires_rerun"
        apple["matrix_source_status"] = "stale_requires_rerun"


def source_manifest_fixture(
    legacy: dict[str, object] | None = None,
) -> dict[str, object]:
    """Return the exact post-migration source-results publication state."""

    if legacy is None:
        legacy = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
    manifest = source_baseline_fixture(legacy)
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
        apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
    ] = apple
    manifest["release_publications"][
        platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY
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
    publications[apple_contract.APPLE_V0_1_4_PUBLICATION_KEY] = apple
    publications[platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY] = platform
    publications[crates_contract.CRATES_IO_PUBLICATION_KEY] = registry
    swift = manifest["swift_xcframework"]
    swift["active_publication_key"] = (
        apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
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

    def test_platform_rebinding_propagates_exact_r_to_security_gate(self) -> None:
        apple_source = stable_pending_receipt()["source"]
        platform = _rebind_platform(platform_pending_receipt(), apple_source)
        observation = platform["observation"]
        gate = observation["candidate_attestation"]["security_gate"]
        tag_commit = apple_source["tag_commit"]

        self.assertEqual(tag_commit, observation["source"]["tag_commit"])
        self.assertEqual(tag_commit, gate["tag_commit"])
        self.assertEqual(
            {tag_commit},
            {workflow["head_sha"] for workflow in gate["workflows"].values()},
        )
        self.assertEqual(
            tag_commit,
            gate["code_scanning"]["main_ref"]["commit_sha"],
        )
        self.assertEqual(
            {tag_commit},
            {
                analysis["commit_sha"]
                for analysis in gate["code_scanning"]["analyses"]
            },
        )

    def test_pending_and_verified_reject_forged_core_source_gates(self) -> None:
        mutations = (
            (
                "Rust status",
                lambda manifest: manifest["rust_publish"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current clean Rust package handoff",
            ),
            (
                "Rust handoff path",
                lambda manifest: manifest["rust_publish"].__setitem__(
                    "handoff_manifest_path", "target/forged.json"
                ),
                "current clean Rust package handoff",
            ),
            (
                "Rust zero transaction sequence",
                lambda manifest: manifest["rust_publish"].__setitem__(
                    "handoff_manifest_path",
                    "target/qperiapt-rust-package-handoffs/"
                    f"transaction.0-{'7' * 32}/rust-package-handoff.json",
                ),
                "current clean Rust package handoff",
            ),
            (
                "Rust upload attempted",
                lambda manifest: manifest["rust_publish"].__setitem__(
                    "upload_attempted", True
                ),
                "current clean Rust package handoff",
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
                "AAR target inventory",
                lambda manifest: manifest["android_aar"].__setitem__(
                    "targets", ["x86_64"]
                ),
                "current clean Android AAR",
            ),
            (
                "runtime status",
                lambda manifest: manifest["android_device_runtime"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current canonical Android runtime evidence",
            ),
            (
                "runtime device kind",
                lambda manifest: manifest["android_device_runtime"].__setitem__(
                    "device_kind", "physical"
                ),
                "current canonical Android runtime evidence",
            ),
            (
                "runtime SDK",
                lambda manifest: manifest["android_device_runtime"].__setitem__(
                    "android_sdk", 36
                ),
                "current canonical Android runtime evidence",
            ),
            (
                "runtime run identity",
                lambda manifest: manifest["android_device_runtime"].__setitem__(
                    "run_id", "bad"
                ),
                "current canonical Android runtime evidence",
            ),
            (
                "runtime proof path",
                lambda manifest: manifest["android_device_runtime"].__setitem__(
                    "proof_path", "../forged.json"
                ),
                "current canonical Android runtime evidence",
            ),
            (
                "index status",
                lambda manifest: manifest["local_release_index"].__setitem__(
                    "current_source_status", "stale_requires_rerun"
                ),
                "current local release consumer receipt",
            ),
            (
                "index runtime crosslink",
                lambda manifest: manifest["local_release_index"].__setitem__(
                    "android_runtime_run_id", "f" * 32
                ),
                "current local release consumer receipt",
            ),
            (
                "index path",
                lambda manifest: manifest["local_release_index"].__setitem__(
                    "index_path", "target/forged.json"
                ),
                "current local release consumer receipt",
            ),
            (
                "consumer receipt path",
                lambda manifest: manifest["local_release_index"].__setitem__(
                    "consumer_receipt_path", "target/forged.json"
                ),
                "current local release consumer receipt",
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

    def test_product_readiness_evidence_is_not_a_publication_prerequisite(self) -> None:
        for state_factory in (self.pending_manifest, self.verified_manifest):
            manifest = state_factory()
            self.assertNotIn("android_physical_runtime", manifest)
            self.assertEqual(
                "stale_requires_rerun",
                manifest["apple_device"]["current_source_status"],
            )
            self.assertEqual(
                "stale_requires_rerun",
                manifest["apple_device"]["matrix_source_status"],
            )
            self.assertEqual(
                "stale_requires_rerun",
                manifest["performance"]["current_source_status"],
            )
            contract.validate_release_publications(manifest)

    def test_stable_source_currentness_is_a_standalone_manifest_authority(
        self,
    ) -> None:
        manifest = self.pending_manifest()
        contract.validate_stable_source_currentness(manifest)
        for label, section, field, value in (
            (
                "runtime path",
                "android_device_runtime",
                "proof_path",
                "target/forged.json",
            ),
            (
                "Rust handoff digest",
                "rust_publish",
                "handoff_manifest_sha256",
                "bad",
            ),
            (
                "consumer digest",
                "local_release_index",
                "consumer_receipt_sha256",
                "bad",
            ),
        ):
            with self.subTest(label=label):
                invalid = copy.deepcopy(manifest)
                invalid[section][field] = value
                with self.assertRaises(
                    contract.ReleasePublicationContractError
                ):
                    contract.validate_stable_source_currentness(invalid)

    def test_retired_legacy_alpha2_selector_fails_closed(self) -> None:
        # The one-time neutral selector migration completed on the
        # published 0.1.3 line: its machinery is deleted, and the exact
        # pre-migration legacy manifest shape is no longer a valid state
        # or a valid transition parent.
        self.assertFalse(hasattr(contract, "neutral_swift_selector"))
        legacy_manifest = legacy_swift_manifest_fixture(self.legacy)
        for field, expected in LEGACY_ALPHA2_SWIFT_FIELDS.items():
            self.assertEqual(
                expected, legacy_manifest["swift_xcframework"][field], field
            )
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError,
            "active Apple selector fields differ",
        ):
            contract.validate_release_publications(legacy_manifest)
        with self.assertRaises(contract.ReleasePublicationContractError):
            contract.validate_release_publication_transition(
                legacy_manifest, self.source_manifest()
            )

    def test_live_manifest_pins_the_complete_frozen_history(self) -> None:
        publications = self.legacy["release_publications"]
        for key in _FROZEN_HISTORICAL_PUBLICATION_KEYS:
            self.assertIn(key, publications)
        for label, key, frozen in (
            (
                "apple alpha2_r1",
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
                alpha2_receipt(),
            ),
            (
                "apple v0_1_3",
                apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
                frozen_apple_v0_1_3_receipt(),
            ),
            (
                "platform v0_1_3",
                platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
                platform_contract.frozen_platform_v0_1_3_receipt(),
            ),
            (
                "crates.io v0_1_3",
                crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
                crates_contract.frozen_crates_io_v0_1_3_receipt(),
            ),
        ):
            with self.subTest(frozen_leaf=label):
                self.assertEqual(frozen, publications[key])

        # The live selector is the migrated neutral selector with the
        # state-selected activation: apple_v0_1_4 once the active cohort
        # verifies, otherwise the frozen published apple_v0_1_3 receipt.
        state = contract.publication_state(self.legacy)
        swift = self.legacy["swift_xcframework"]
        for field, expected in (
            ("boundary", contract.NEUTRAL_SWIFT_BOUNDARY),
            ("command", contract.NEUTRAL_SWIFT_COMMAND),
            ("current_local_status", contract.NEUTRAL_SWIFT_LOCAL_STATUS),
            ("current_source_status", contract.NEUTRAL_SWIFT_SOURCE_STATUS),
            ("mode", contract.NEUTRAL_SWIFT_MODE),
        ):
            self.assertEqual(expected, swift[field], field)
        expected_active = (
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
            if state == contract.PUBLICATION_STATE_VERIFIED
            else apple_contract.APPLE_V0_1_3_PUBLICATION_KEY
        )
        self.assertEqual(expected_active, swift["active_publication_key"])
        self.assertEqual(
            publications[expected_active]["distribution"],
            swift["distribution"],
        )

        # The committed state is a valid transition fixed point, and the
        # synthetic source rebinding remains a legal successor of the
        # live manifest's source-results baseline.
        contract.validate_release_publication_transition(
            self.legacy, self.legacy
        )
        contract.validate_release_publication_transition(
            source_baseline_fixture(self.legacy), self.source_manifest()
        )

    def test_pending_requires_both_domains_and_never_changes_selector(self) -> None:
        source = self.source_manifest()
        pending = self.pending_manifest()
        for missing in (
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY,
            platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY,
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
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
        )
        activated["swift_xcframework"]["distribution"] = copy.deepcopy(
            activated["release_publications"][
                apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
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
                apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
            ],
            leaf,
        )
        self.assertEqual(
            apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
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
            apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
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
                    platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY
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
        for key in _FROZEN_HISTORICAL_PUBLICATION_KEYS:
            with self.subTest(key=key, mutation="changed"):
                changed = copy.deepcopy(pending)
                changed["release_publications"][key]["boundary"] += " changed"
                with self.assertRaises(contract.ReleasePublicationContractError):
                    contract.validate_release_publication_transition(pending, changed)
            with self.subTest(key=key, mutation="removed"):
                removed = copy.deepcopy(pending)
                removed["release_publications"].pop(key)
                with self.assertRaises(contract.ReleasePublicationContractError):
                    contract.validate_release_publication_transition(pending, removed)

        unknown = self.source_manifest()
        unknown["release_publications"]["future_publication"] = {}
        with self.assertRaisesRegex(
            contract.ReleasePublicationContractError, "unknown entries"
        ):
            contract.validate_release_publications(unknown)


if __name__ == "__main__":
    unittest.main()
