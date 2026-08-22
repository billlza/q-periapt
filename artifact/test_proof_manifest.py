from __future__ import annotations

import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import performance_gate
import proof_manifest
import release_publication_contract
import rust_package_handoff
import rust_publish_contract
from evidence_io import FileSnapshot
from proof_manifest import (
    ProofManifestError,
    load_current_rust_package_contract_receipt,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)


class ProofManifestTests(unittest.TestCase):
    RUST_HANDOFF_TRANSACTION = f"transaction.1-{'1' * 32}"
    RUST_HANDOFF_MANIFEST_PATH = (
        "target/qperiapt-rust-package-handoffs/"
        f"{RUST_HANDOFF_TRANSACTION}/rust-package-handoff.json"
    )
    RUST_HANDOFF_TRANSCRIPT_PATH = (
        "target/qperiapt-rust-package-handoffs/"
        f"{RUST_HANDOFF_TRANSACTION}/rust-package-contract.log"
    )
    def test_performance_schema_constant_matches_the_live_gate(self) -> None:
        self.assertEqual(proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION, 8)
        self.assertEqual(
            proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
            performance_gate.PROOF_SCHEMA_VERSION,
        )
        self.assertEqual(
            proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
            release_publication_contract._STABLE_PERFORMANCE_PROOF_SCHEMA,
        )

    def test_rust_package_schema_constants_match_the_live_contract(self) -> None:
        self.assertEqual(
            proof_manifest.RUST_PACKAGE_PUBLISHABLE_CRATES,
            rust_publish_contract.RUST_PUBLISHABLE_CRATES,
        )
        self.assertEqual(
            proof_manifest.RUST_PACKAGE_ADVISORY_DB_URL,
            rust_publish_contract.RUSTSEC_ADVISORY_DB_URL,
        )
        self.assertEqual(
            proof_manifest.RUST_CRATES_IO_SPARSE_INDEX,
            rust_publish_contract.RUST_CRATES_IO_SPARSE_INDEX,
        )

    def current_rust_package_manifest(self) -> dict[str, object]:
        digest = "a" * 64
        commit = "c" * 40
        completed_at = "2026-08-13T02:59:07Z"
        advisory_commit = "d" * 40
        return {
            "proof_source_tree_sha256": digest,
            "provenance": {"snapshot_commit": commit},
            "rust_publish": {
                "advisory_db_commit": advisory_commit,
                "advisory_db_mode": proof_manifest.RUST_PACKAGE_ADVISORY_DB_MODE,
                "advisory_db_url": proof_manifest.RUST_PACKAGE_ADVISORY_DB_URL,
                "advisory_db_clean": True,
                "boundary": proof_manifest.RUST_PACKAGE_BOUNDARY,
                "cargo_audit_version": "0.22.2",
                "cargo_home_isolated": True,
                "cargo_version": "1.96.1",
                "cargo_warning_free": True,
                "command": proof_manifest.RUST_PACKAGE_COMMAND,
                "completed_at": completed_at,
                "crates_io_index_protocol": (
                    proof_manifest.RUST_PACKAGE_CRATES_IO_INDEX_PROTOCOL
                ),
                "crates_io_index_url": proof_manifest.RUST_CRATES_IO_SPARSE_INDEX,
                "crates_io_registry_package_count": 2,
                "crates_io_sparse_lock_verification_pass": True,
                "current_local_status": proof_manifest.rust_package_current_local_status(
                    source_commit=commit,
                    source_digest=digest,
                    completed_at=completed_at,
                    advisory_commit=advisory_commit,
                    registry_package_count=2,
                    normalized_lock_sha256="f" * 64,
                ),
                "current_source_status": (
                    "current_clean_tree_rust_package_contract_pass"
                ),
                "dirty_diagnostic_command": (
                    proof_manifest.RUST_PACKAGE_DIRTY_COMMAND
                ),
                "evidence_schema": 2,
                "handoff_manifest_path": self.RUST_HANDOFF_MANIFEST_PATH,
                "handoff_manifest_sha256": "9" * 64,
                "mode": proof_manifest.RUST_PACKAGE_MODE,
                "nonpublishable_crates": list(
                    proof_manifest.RUST_PACKAGE_NONPUBLISHABLE_CRATES
                ),
                "normalized_cargo_lock_sha256": "f" * 64,
                "normalized_dependency_audit_pass": True,
                "package_list_pass_crates": list(
                    proof_manifest.RUST_PACKAGE_PUBLISHABLE_CRATES
                ),
                "package_verification_pass_crates": list(
                    proof_manifest.RUST_PACKAGE_PUBLISHABLE_CRATES
                ),
                "proof_source_tree_sha256": digest,
                "publishable_crates": list(
                    proof_manifest.RUST_PACKAGE_PUBLISHABLE_CRATES
                ),
                "registry": "crates-io",
                "rustc_version": "1.96.1",
                "source_commit": commit,
                "source_tree_dirty": False,
                "status": "pass",
                "transcript_path": self.RUST_HANDOFF_TRANSCRIPT_PATH,
                "transcript_sha256": "e" * 64,
                "upload_attempted": False,
            },
        }

    def current_rust_package_transcript(
        self,
        *,
        source_commit: str = "c" * 40,
        advisory_commit: str = "d" * 40,
        completed_at: str = "2026-08-13T02:59:07Z",
    ) -> bytes:
        lines = [
            rust_publish_contract.RUST_PACKAGE_CARGO_HOME_MARKER,
            rust_publish_contract.RUST_PACKAGE_TOOLCHAIN_MARKER,
            f"RUST_PACKAGE_SOURCE_PASS commit={source_commit} clean=1",
            "RUST_CARGO_WARNING_FREE_PASS cargo-metadata",
            rust_publish_contract.RUST_MLKEM_PROVIDER_FENCE_MARKER,
            rust_publish_contract.RUST_PUBLISH_METADATA_MARKER,
        ]
        for crate in rust_publish_contract.RUST_PUBLISHABLE_CRATES:
            lines.extend(
                (
                    f"RUST_CARGO_WARNING_FREE_PASS cargo-package-list-{crate}",
                    f"RUST_PACKAGE_LIST_PASS {crate} files=1",
                )
            )
        for crate in rust_publish_contract.RUST_PUBLISHABLE_CRATES:
            lines.extend(
                (
                    "RUST_CARGO_WARNING_FREE_PASS "
                    f"cargo-package-verification-{crate}",
                    f"RUST_PACKAGE_COMPLETION_PASS {crate}",
                    "RUST_PACKAGE_VERIFICATION_PASS "
                    f"{crate} registry=crates-io upload=not-attempted",
                )
            )
        lines.extend(
            (
                rust_publish_contract.RUST_PACKAGE_VERIFICATION_CLEANUP_MARKER,
                "RUST_CARGO_WARNING_FREE_PASS "
                "cargo-package-inspection-q-periapt-mlkem-native-sys",
                "RUST_PACKAGE_COMPLETION_PASS q-periapt-mlkem-native-sys",
                "RUST_MLKEM_NATIVE_SYS_ARCHIVE_BINARY_PASS "
                "target=aarch64-apple-darwin implementation=aarch64-native "
                "implementation_id=mlkem-native-1.2.0/"
                "aarch64-native-arith+fips202-v84a "
                "objects=2 symbols=42 reserved_dynamic_abi=none",
                "RUST_MLKEM_NATIVE_SYS_ARCHIVE_PASS vendor_files=118 "
                "upstream=v1.2.0 commit="
                + rust_publish_contract.RUST_MLKEM_UPSTREAM_COMMIT,
                "RUST_CARGO_WARNING_FREE_PASS "
                "cargo-package-inspection-q-periapt-backends",
                "RUST_PACKAGE_COMPLETION_PASS q-periapt-backends",
                rust_publish_contract.RUST_BACKENDS_INSPECTION_MARKER,
                rust_publish_contract.RUST_BACKENDS_NORMALIZED_MANIFEST_MARKER,
                "RUST_CARGO_WARNING_FREE_PASS "
                "cargo-generate-normalized-backends-lockfile",
                "RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=2 "
                "index=sparse-https checksums=exact yanked=0 "
                f"normalized_lock_sha256={'f' * 64}",
                "RUST_CARGO_WARNING_FREE_PASS cargo-audit-normalized-backends",
                rust_publish_contract.RUST_PACKAGE_NORMALIZED_AUDIT_MARKER,
                "RUST_ADVISORY_DB_PASS "
                f"origin={rust_publish_contract.RUSTSEC_ADVISORY_DB_URL} "
                f"commit={advisory_commit} clean=1 isolated_cargo_home=1",
                f"RUST_NORMALIZED_LOCK_STABILITY_PASS sha256={'f' * 64}",
                rust_publish_contract.RUST_PACKAGE_INSPECTION_CLEANUP_MARKER,
                rust_publish_contract.RUST_PACKAGE_CARGO_HOME_CLEANUP_MARKER,
                "RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io "
                f"upload=not-attempted completed_at={completed_at}",
            )
        )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def performance_manifest(
        self,
        relative: str,
        digest: str,
    ) -> dict[str, object]:
        source_digest = "a" * 64
        return {
            "proof_source_tree_sha256": source_digest,
            "performance": {
                "current_source_status": "current_controlled_pass",
                "proof_schema": proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
                "proof_source_tree_sha256": source_digest,
                "proof_path": relative,
                "proof_sha256": digest,
                "proof_generated_at": "2026-08-12T00:00:00Z",
                "status": "pass",
            },
        }

    def current_android_manifest(
        self,
        *,
        device_kind: str = "emulator",
    ) -> dict[str, object]:
        digest = "a" * 64
        commit = "c" * 40
        run_id = "d" * 32
        status = f"current_clean_tree_{device_kind}_pass"
        runtime = {
            "android_sdk": 35 if device_kind == "emulator" else 36,
            "build_tools": "36.0.0",
            "covered_tests": list(proof_manifest.ANDROID_EXPECTED_TESTS),
            "current_source_status": status,
            "device_abi": "arm64-v8a",
            "device_kind": device_kind,
            "page_size": 16_384 if device_kind == "emulator" else 4_096,
            "proof_generated_at": "2026-08-12T00:00:00Z",
            "proof_path": (
                f"target/qperiapt-android-device-smoke-runs/{run_id}/proof/"
                "qperiapt-android-device-proof.json"
            ),
            "proof_schema": proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            "proof_sha256": "b" * 64,
            "proof_source_tree_sha256": digest,
            "release_candidate_mode": device_kind == "emulator",
            "run_id": run_id,
            "source_commit": commit,
            "source_tree_dirty": False,
            "status": "pass",
        }
        runtime_section = (
            "android_device_runtime"
            if device_kind == "emulator"
            else "android_physical_runtime"
        )
        return {
            "android_aar": {
                "aar_path": proof_manifest.ANDROID_AAR_PATH,
                "aar_sha256": "e" * 64,
                "current_source_status": "current_clean_tree_package_pass",
                "manifest_generated_at": "2026-08-12T00:00:00Z",
                "manifest_path": proof_manifest.ANDROID_AAR_MANIFEST_PATH,
                "manifest_schema": 4,
                "manifest_sha256": "f" * 64,
                "proof_source_tree_sha256": digest,
                "source_commit": commit,
                "source_tree_dirty": False,
                "status": "pass",
                "targets": list(proof_manifest.ANDROID_ABIS),
            },
            runtime_section: runtime,
            "proof_source_tree_sha256": digest,
            "provenance": {"snapshot_commit": commit},
        }

    def test_declared_current_performance_rejects_stale_schema_or_source(self) -> None:
        digest = "a" * 64
        current = {
            "proof_source_tree_sha256": digest,
            "performance": {
                "current_source_status": "current_controlled_pass",
                "proof_schema": proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
                "proof_source_tree_sha256": digest,
                "proof_path": "target/performance/proof.json",
                "proof_sha256": "b" * 64,
                "proof_generated_at": "2026-07-11T00:00:00Z",
                "status": "pass",
            },
        }
        proof_manifest.validate_declared_currentness(current)
        current["performance"]["proof_schema"] = (
            proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION - 1
        )
        with self.assertRaisesRegex(
                proof_manifest.ProofManifestError,
                f"requires proof schema {proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION}",
        ):
            proof_manifest.validate_declared_currentness(current)
        current["performance"]["proof_schema"] = (
            proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION
        )
        current["performance"]["proof_source_tree_sha256"] = "b" * 64
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "does not match"
        ):
            proof_manifest.validate_declared_currentness(current)

    def test_declared_current_performance_requires_bound_path_hash_and_pass(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_controlled_pass",
            "proof_schema": proof_manifest.PERFORMANCE_PROOF_SCHEMA_VERSION,
            "proof_source_tree_sha256": digest,
            "proof_path": "target/performance/proof.json",
            "proof_sha256": "b" * 64,
            "proof_generated_at": "2026-07-11T00:00:00Z",
            "status": "pass",
        }
        manifest = {"proof_source_tree_sha256": digest, "performance": section}
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("proof_path", "../proof.json", "selected-proof path"),
            ("proof_sha256", "bad", "selected-proof SHA-256"),
            ("status", "fail", "passing proof"),
            ("proof_generated_at", None, "generation time"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_declared_current_apple_requires_bound_passing_current_schema_attempt(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_clean_tree_physical_pass",
            "current_proof_schema": proof_manifest.APPLE_DEVICE_PROOF_SCHEMA_VERSION,
            "proof_source_tree_sha256": digest,
            "current_proof_path": "artifact/device-runs/ipad/proof.json",
            "current_proof_sha256": "b" * 64,
            "current_proof_generated_at": "2026-07-11T00:00:00Z",
            "current_proof_source_tree_dirty": False,
            "current_attempt": {"status": "pass", "proof_emitted": True},
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)
        section["current_attempt"] = {"status": "fail", "proof_emitted": False}
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "passing emitted-proof attempt"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_current_apple_status_rejects_mismatched_cleanliness(self) -> None:
        digest = "a" * 64
        section = {
            "current_source_status": "current_dirty_diagnostic_pass",
            "current_proof_schema": proof_manifest.APPLE_DEVICE_PROOF_SCHEMA_VERSION,
            "proof_source_tree_sha256": digest,
            "current_proof_path": "artifact/device-runs/ipad/proof.json",
            "current_proof_sha256": "b" * 64,
            "current_proof_generated_at": "2026-07-11T00:00:00Z",
            "current_proof_source_tree_dirty": False,
            "current_attempt": {"status": "pass", "proof_emitted": True},
        }
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "inconsistent source-tree cleanliness"
        ):
            proof_manifest.validate_declared_currentness(
                {"proof_source_tree_sha256": digest, "apple_device": section}
            )

    def test_declared_current_apple_matrix_requires_bound_passing_current_schema_proof(self) -> None:
        digest = "a" * 64
        section = {
            "matrix_source_status": "current_clean_tree_physical_pass",
            "matrix_proof_schema": proof_manifest.APPLE_MATRIX_PROOF_SCHEMA_VERSION,
            "proof_source_tree_sha256": digest,
            "matrix_proof_path": "artifact/device-runs/matrix/apple-device-matrix-proof.json",
            "matrix_proof_sha256": "b" * 64,
            "matrix_generated_at": "2026-07-11T00:00:00Z",
            "matrix_status": "pass",
            "matrix_source_tree_dirty": False,
        }
        manifest = {"proof_source_tree_sha256": digest, "apple_device": section}
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("matrix_proof_path", "../proof.json", "selected-proof path"),
            ("matrix_proof_sha256", "bad", "selected-proof SHA-256"),
            (
                "matrix_proof_schema",
                proof_manifest.APPLE_MATRIX_PROOF_SCHEMA_VERSION - 1,
                f"requires proof schema {proof_manifest.APPLE_MATRIX_PROOF_SCHEMA_VERSION}",
            ),
            ("proof_source_tree_sha256", "c" * 64, "does not match"),
            ("matrix_status", "fail", "passing proof"),
            ("matrix_generated_at", None, "generation time"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

        manifest.pop("proof_source_tree_sha256")
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError, "does not match"
        ):
            proof_manifest.validate_declared_currentness(manifest)

    def test_noncurrent_apple_matrix_does_not_require_current_proof_fields(self) -> None:
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "apple_device": {"matrix_source_status": "stale_requires_rerun"},
            }
        )

    def test_declared_current_android_requires_bound_passing_current_schema_proof(self) -> None:
        manifest = self.current_android_manifest()
        section = manifest["android_device_runtime"]
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("proof_path", "../proof.json", "selected-proof path"),
            ("proof_sha256", "bad", "selected-proof SHA-256"),
            (
                "proof_schema",
                proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION - 1,
                (
                    "requires proof schema "
                    f"{proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION}"
                ),
            ),
            ("proof_source_tree_sha256", "c" * 64, "does not match"),
            ("status", "fail", "passing proof"),
            ("proof_generated_at", None, "generation time"),
            ("source_tree_dirty", True, "clean source provenance"),
            ("android_sdk", "35", "SDK is invalid"),
            ("page_size", True, "page size is invalid"),
            ("covered_tests", [], "exact runtime test set"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(proof_manifest.ProofManifestError, message):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_current_android_status_is_bound_to_the_declared_device_kind(self) -> None:
        for declared_kind, status_kind in (
            ("physical", "emulator"),
            ("emulator", "physical"),
        ):
            with self.subTest(declared_kind=declared_kind, status_kind=status_kind):
                manifest = self.current_android_manifest(device_kind=declared_kind)
                runtime_section = (
                    "android_device_runtime"
                    if declared_kind == "emulator"
                    else "android_physical_runtime"
                )
                runtime = manifest[runtime_section]
                runtime["current_source_status"] = (
                    f"current_clean_tree_{status_kind}_pass"
                )
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    "unknown status",
                ):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_canonical_and_physical_android_runtime_can_be_current_together(
        self,
    ) -> None:
        manifest = self.current_android_manifest()
        physical = self.current_android_manifest(device_kind="physical")
        manifest["android_physical_runtime"] = physical["android_physical_runtime"]
        proof_manifest.validate_declared_currentness(manifest)

        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(manifest),
            "emulator",
        )
        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(
                manifest,
                binding="android_physical_runtime",
            ),
            "physical",
        )
        self.assertIs(
            proof_manifest.current_android_runtime_section(manifest),
            manifest["android_device_runtime"],
        )
        self.assertIs(
            proof_manifest.current_android_runtime_section(
                manifest,
                binding="android_physical_runtime",
            ),
            manifest["android_physical_runtime"],
        )

    def test_current_physical_runtime_allows_real_device_characteristics(self) -> None:
        manifest = self.current_android_manifest(device_kind="physical")
        section = manifest["android_physical_runtime"]
        section.update(
            {
                "device_abi": "armeabi-v7a",
                "page_size": 4_096,
                "android_sdk": 37,
                "release_candidate_mode": False,
                "build_tools": "37.0.0-rc1",
            }
        )
        proof_manifest.validate_declared_currentness(manifest)

        for field, bad_value, message in (
            ("device_abi", "mips", "ABI is invalid"),
            ("page_size", 8_192, "page size is invalid"),
            ("android_sdk", 0, "SDK is invalid"),
            ("release_candidate_mode", 1, "release mode is invalid"),
            (
                "proof_schema",
                proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION - 1,
                f"proof schema {proof_manifest.ANDROID_DEVICE_PROOF_SCHEMA_VERSION}",
            ),
            ("status", "fail", "passing proof"),
            ("source_tree_dirty", True, "clean source provenance"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_runtime_binding_selection_never_falls_back_between_sections(self) -> None:
        canonical = self.current_android_manifest()
        canonical["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        physical = self.current_android_manifest(device_kind="physical")
        canonical["android_physical_runtime"] = physical["android_physical_runtime"]

        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "current emulator runtime status",
        ):
            proof_manifest.current_android_runtime_section(canonical)
        self.assertEqual(
            proof_manifest.expected_android_runtime_device_kind(
                canonical,
                binding="android_physical_runtime",
            ),
            "physical",
        )
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "unknown Android runtime results binding",
        ):
            proof_manifest.select_android_runtime_results_binding("physical")

    def test_current_android_emulator_requires_the_canonical_release_runtime(self) -> None:
        for field, bad_value in (
            ("device_abi", "x86_64"),
            ("page_size", 4_096),
            ("android_sdk", 36),
            ("release_candidate_mode", False),
            ("build_tools", "35.0.0"),
        ):
            with self.subTest(field=field):
                manifest = self.current_android_manifest()
                manifest["android_device_runtime"][field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    "canonical release runtime",
                ):
                    proof_manifest.validate_declared_currentness(manifest)

    def test_current_android_aar_requires_exact_source_paths_and_targets(self) -> None:
        manifest = self.current_android_manifest()
        manifest["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        section = manifest["android_aar"]
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("aar_path", "target/other.aar", "path is not canonical"),
            ("manifest_sha256", "bad", "selected-proof SHA-256"),
            ("manifest_schema", 3, "manifest schema 4"),
            ("targets", list(reversed(proof_manifest.ANDROID_ABIS)), "four ABI"),
            ("source_commit", "0" * 40, "source commit"),
            ("source_tree_dirty", True, "clean source provenance"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_current_rust_package_contract_requires_exact_clean_no_upload_evidence(
        self,
    ) -> None:
        manifest = self.current_rust_package_manifest()
        proof_manifest.validate_declared_currentness(manifest)
        section = manifest["rust_publish"]
        mutations = (
            ("evidence_schema", True, "exact evidence_schema"),
            ("status", "diagnostic", "exact status"),
            ("command", "cargo package", "exact command"),
            ("dirty_diagnostic_command", "sh old.sh", "exact dirty_diagnostic"),
            ("mode", "cargo publish --dry-run", "exact mode"),
            ("boundary", "release ready", "exact boundary"),
            ("current_local_status", "historical dry run", "exact current_local_status"),
            ("registry", "other", "exact registry"),
            ("upload_attempted", True, "exact upload_attempted"),
            ("rustc_version", "1.96.0", "exact rustc_version"),
            ("cargo_version", "1.96.0", "exact cargo_version"),
            ("cargo_audit_version", "0.22.1", "exact cargo_audit_version"),
            (
                "crates_io_index_protocol",
                "git",
                "exact crates_io_index_protocol",
            ),
            (
                "crates_io_index_url",
                "https://example.invalid",
                "exact crates_io_index_url",
            ),
            (
                "crates_io_sparse_lock_verification_pass",
                False,
                "exact crates_io_sparse_lock_verification_pass",
            ),
            (
                "crates_io_registry_package_count",
                0,
                "bounded crates.io registry package count",
            ),
            (
                "crates_io_registry_package_count",
                rust_publish_contract.RUST_SPARSE_MAX_REGISTRY_PACKAGES + 1,
                "bounded crates.io registry package count",
            ),
            ("advisory_db_mode", "ambient", "exact advisory_db_mode"),
            ("advisory_db_url", "https://example.invalid", "exact advisory_db_url"),
            ("advisory_db_clean", False, "exact advisory_db_clean"),
            ("cargo_home_isolated", False, "exact cargo_home_isolated"),
            ("cargo_warning_free", False, "exact cargo_warning_free"),
            (
                "normalized_dependency_audit_pass",
                False,
                "exact normalized_dependency_audit_pass",
            ),
            (
                "normalized_cargo_lock_sha256",
                "bad",
                "normalized Cargo.lock SHA-256",
            ),
            ("publishable_crates", [], "exact publishable_crates"),
            ("nonpublishable_crates", [], "exact nonpublishable_crates"),
            ("package_list_pass_crates", [], "exact package_list_pass_crates"),
            (
                "package_verification_pass_crates",
                [],
                "exact package_verification_pass_crates",
            ),
            ("source_commit", "0" * 40, "source commit"),
            ("proof_source_tree_sha256", "0" * 64, "source digest"),
            ("source_tree_dirty", True, "clean source provenance"),
            ("advisory_db_commit", "bad", "advisory DB commit"),
            ("completed_at", "2026-08-13", "RFC3339 UTC completion"),
            ("completed_at", "2026-8-3T2:3:4Z", "RFC3339 UTC completion"),
            (
                "handoff_manifest_path",
                "target/other.json",
                "handoff manifest path is not canonical",
            ),
            (
                "handoff_manifest_sha256",
                "bad",
                "selected-proof SHA-256",
            ),
            ("transcript_path", "target/other.log", "not canonical"),
            ("transcript_sha256", "bad", "selected-proof SHA-256"),
        )
        for field, bad_value, message in mutations:
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

        for field in (
            "publishable_crates",
            "package_list_pass_crates",
            "package_verification_pass_crates",
        ):
            original = section[field]
            for label, bad_value in (
                ("reordered", list(reversed(original))),
                ("duplicate", [*original, original[0]]),
                ("extra", [*original, "q-periapt-unclassified"]),
            ):
                with self.subTest(field=field, mutation=label):
                    section[field] = bad_value
                    with self.assertRaisesRegex(
                        ProofManifestError,
                        f"exact {field}",
                    ):
                        proof_manifest.validate_declared_currentness(manifest)
            section[field] = original

    def test_current_rust_package_transcript_uses_the_canonical_file_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            handoff_manifest = root / self.RUST_HANDOFF_MANIFEST_PATH
            transcript = root / self.RUST_HANDOFF_TRANSCRIPT_PATH
            transcript.parent.mkdir(parents=True)
            handoff_manifest.write_text("{}\n", encoding="utf-8")
            transcript.write_text("receipt\n", encoding="utf-8")
            manifest_value = self.current_rust_package_manifest()
            manifest_value["rust_publish"]["handoff_manifest_sha256"] = (
                hashlib.sha256(handoff_manifest.read_bytes()).hexdigest()
            )
            manifest_value["rust_publish"]["transcript_sha256"] = hashlib.sha256(
                transcript.read_bytes()
            ).hexdigest()
            artifact = root / "artifact"
            artifact.mkdir()
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(manifest_value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            declaration = proof_manifest.resolve_bound_file_declaration(
                root,
                manifest,
                binding="rust_package_transcript",
            )
            self.assertEqual(declaration.path, transcript)
            self.assertEqual(
                declaration.sha256,
                manifest_value["rust_publish"]["transcript_sha256"],
            )
            handoff_declaration = proof_manifest.resolve_bound_file_declaration(
                root,
                manifest,
                binding="rust_package_handoff_manifest",
            )
            self.assertEqual(handoff_declaration.path, handoff_manifest)
            self.assertEqual(
                handoff_declaration.sha256,
                manifest_value["rust_publish"]["handoff_manifest_sha256"],
            )

    def test_current_rust_package_receipt_loads_exact_bound_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            handoff_manifest = root / self.RUST_HANDOFF_MANIFEST_PATH
            transcript = root / self.RUST_HANDOFF_TRANSCRIPT_PATH
            transcript.parent.mkdir(parents=True)
            handoff_manifest.write_text("{}\n", encoding="utf-8")
            transcript.write_bytes(self.current_rust_package_transcript())
            manifest_value = self.current_rust_package_manifest()
            manifest_value["rust_publish"]["transcript_sha256"] = hashlib.sha256(
                transcript.read_bytes()
            ).hexdigest()
            artifact = root / "artifact"
            artifact.mkdir()
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(manifest_value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            receipt_fixture = (
                rust_publish_contract.validate_rust_package_contract_transcript(
                    transcript.read_bytes()
                )
            )
            handoff_snapshot = mock.Mock(
                transcript=FileSnapshot(
                    path=transcript,
                    data=transcript.read_bytes(),
                    size=transcript.stat().st_size,
                    sha256=manifest_value["rust_publish"][
                        "transcript_sha256"
                    ],
                ),
                package_contract=receipt_fixture,
            )
            with (
                mock.patch.object(
                    proof_manifest,
                    "run_git_text",
                    return_value="4" * 40,
                ) as source_tree,
                mock.patch.object(
                    rust_package_handoff,
                    "load_rust_package_handoff_snapshot",
                    return_value=handoff_snapshot,
                ) as load_handoff,
                mock.patch.object(
                    proof_manifest,
                    "require_commit_or_evidence_successor",
                    return_value="e" * 40,
                ) as source_successor,
            ):
                receipt = load_current_rust_package_contract_receipt(
                    root,
                    manifest,
                    frozen_commit="e" * 40,
                    frozen_source_sha256="a" * 64,
                )
            source_tree.assert_called_once_with(
                root,
                ["rev-parse", "--verify", f"{'c' * 40}^{{tree}}"],
            )
            load_handoff.assert_called_once_with(
                handoff_manifest,
                "9" * 64,
                rust_package_handoff.RustPackageHandoffSource(
                    source_commit="c" * 40,
                    source_tree="4" * 40,
                    canonical_source_tree_sha256="a" * 64,
                ),
                handoff_root=(
                    root / "target" / "qperiapt-rust-package-handoffs"
                ),
            )
            source_successor.assert_called_once_with(root, "c" * 40)
            self.assertEqual(receipt.source_commit, "c" * 40)
            self.assertEqual(receipt.advisory_db_commit, "d" * 40)
            self.assertEqual(receipt.registry_package_count, 2)
            self.assertEqual(receipt.normalized_cargo_lock_sha256, "f" * 64)

            for label, message in (
                ("handoff", "handoff digest differs"),
                ("commit", "source commit differs"),
            ):
                with self.subTest(label=label):
                    selected_source_commit = (
                        "c" * 40 if label == "handoff" else "e" * 40
                    )
                    manifest.value["provenance"]["snapshot_commit"] = (
                        selected_source_commit
                    )
                    with self.assertRaisesRegex(ProofManifestError, message):
                        with (
                            mock.patch.object(
                                proof_manifest,
                                "run_git_text",
                                return_value="4" * 40,
                            ),
                            mock.patch.object(
                                rust_package_handoff,
                                "load_rust_package_handoff_snapshot",
                                side_effect=(
                                    rust_package_handoff.RustPackageHandoffError(
                                        "handoff digest differs"
                                    )
                                    if label == "handoff"
                                    else None
                                ),
                                return_value=handoff_snapshot,
                            ),
                            mock.patch.object(
                                proof_manifest,
                                "require_commit_or_evidence_successor",
                                return_value="e" * 40,
                            ),
                        ):
                            load_current_rust_package_contract_receipt(
                                root,
                                manifest,
                                frozen_commit="e" * 40,
                                frozen_source_sha256="a" * 64,
                            )

            manifest.value["provenance"]["snapshot_commit"] = "c" * 40
            manifest.value["rust_publish"]["normalized_cargo_lock_sha256"] = (
                "0" * 64
            )
            with self.assertRaisesRegex(
                ProofManifestError,
                "normalized Cargo.lock SHA-256 differs",
            ):
                with (
                    mock.patch.object(
                        proof_manifest,
                        "run_git_text",
                        return_value="4" * 40,
                    ),
                    mock.patch.object(
                        rust_package_handoff,
                        "load_rust_package_handoff_snapshot",
                        return_value=handoff_snapshot,
                    ),
                    mock.patch.object(
                        proof_manifest,
                        "require_commit_or_evidence_successor",
                        return_value="e" * 40,
                    ),
                ):
                    load_current_rust_package_contract_receipt(
                        root,
                        manifest,
                        frozen_commit="e" * 40,
                        frozen_source_sha256="a" * 64,
                    )

    def test_current_rust_package_contract_rejects_missing_and_extra_fields(self) -> None:
        for label, mutate in (
            ("extra", lambda section: section.__setitem__("registry_uploaded", True)),
            ("missing", lambda section: section.pop("upload_attempted")),
        ):
            manifest = self.current_rust_package_manifest()
            mutate(manifest["rust_publish"])
            with self.subTest(label=label), self.assertRaisesRegex(
                ProofManifestError,
                "field set differs",
            ):
                proof_manifest.validate_declared_currentness(manifest)

    def test_current_local_index_requires_exact_runtime_and_consumer_receipt(self) -> None:
        manifest = self.current_android_manifest()
        commit = manifest["provenance"]["snapshot_commit"]
        runtime = manifest["android_device_runtime"]
        receipt_run_id = "9" * 32
        section = {
            "android_runtime_proof_sha256": runtime["proof_sha256"],
            "android_runtime_run_id": runtime["run_id"],
            "channel": "release",
            "consumer_receipt_generated_at": "2026-08-12T00:05:00Z",
            "consumer_receipt_path": (
                "target/qperiapt-release-consumer-smoke/receipts/"
                f"{receipt_run_id}/qperiapt-release-consumer-receipt.json"
            ),
            "consumer_receipt_run_id": receipt_run_id,
            "consumer_receipt_schema": 1,
            "consumer_receipt_sha256": "8" * 64,
            "consumer_status": "pass",
            "current_source_status": (
                "current_clean_tree_local_index_consumer_pass"
            ),
            "generated_at": "2026-08-12T00:04:00Z",
            "index_path": (
                "target/qperiapt-local-release/release/0.1.2/"
                f"{commit}/index.json"
            ),
            "index_schema": 5,
            "index_sha256": "7" * 64,
            "proof_source_tree_sha256": manifest["proof_source_tree_sha256"],
            "source_commit": commit,
            "source_tree_dirty": False,
            "status": "pass",
        }
        manifest["local_release_index"] = section
        proof_manifest.validate_declared_currentness(manifest)
        for field, bad_value, message in (
            ("channel", "diagnostic", "release channel"),
            ("index_schema", 4, "index schema 5"),
            ("consumer_receipt_schema", True, "receipt schema 1"),
            ("android_runtime_run_id", "1" * 32, "selection differs"),
            ("consumer_receipt_path", "target/receipt.json", "not canonical"),
        ):
            with self.subTest(field=field):
                original = section[field]
                section[field] = bad_value
                with self.assertRaisesRegex(
                    proof_manifest.ProofManifestError,
                    message,
                ):
                    proof_manifest.validate_declared_currentness(manifest)
                section[field] = original

    def test_stale_android_runtime_cannot_be_selected(self) -> None:
        manifest = self.current_android_manifest()
        manifest["android_device_runtime"]["current_source_status"] = (
            "stale_requires_rerun"
        )
        with self.assertRaisesRegex(
            proof_manifest.ProofManifestError,
            "requires a current emulator runtime status",
        ):
            proof_manifest.expected_android_runtime_device_kind(manifest)

    def test_noncurrent_android_does_not_require_current_proof_fields(self) -> None:
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "android_device_runtime": {"current_source_status": "stale_requires_rerun"},
            }
        )

    def test_stale_rust_package_contract_does_not_require_current_fields(self) -> None:
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "rust_publish": {
                    "current_source_status": "stale_requires_rerun"
                },
            }
        )

    def test_rust_package_contract_section_must_be_an_object(self) -> None:
        with self.assertRaisesRegex(ProofManifestError, "rust_publish must be an object"):
            proof_manifest.validate_declared_currentness({"rust_publish": "pass"})

    def test_generic_manifest_preserves_stale_physical_and_performance_history(
        self,
    ) -> None:
        stale = "stale_requires_rerun"
        proof_manifest.validate_declared_currentness(
            {
                "proof_source_tree_sha256": "a" * 64,
                "android_physical_runtime": {
                    "current_source_status": stale,
                    "proof_path": "target/android/historical-physical.json",
                    "proof_sha256": "b" * 64,
                    "historical_device": "retained-fact",
                },
                "performance": {
                    "current_source_status": stale,
                    "proof_path": "target/performance/historical.json",
                    "proof_sha256": "c" * 64,
                    "historical_command": "retained-fact",
                },
            }
        )

    def test_unknown_currentness_statuses_fail_closed(self) -> None:
        for section, key in (
            ("performance", "current_source_status"),
            ("apple_device", "current_source_status"),
            ("apple_device", "matrix_source_status"),
            ("android_device_runtime", "current_source_status"),
            ("android_physical_runtime", "current_source_status"),
            ("android_aar", "current_source_status"),
            ("local_release_index", "current_source_status"),
            ("rust_publish", "current_source_status"),
        ):
            with self.subTest(section=section, key=key), self.assertRaisesRegex(
                proof_manifest.ProofManifestError,
                "unknown status",
            ):
                proof_manifest.validate_declared_currentness(
                    {section: {key: "current_pass_typo"}}
                )

    def test_every_manifest_bound_file_rejects_a_stale_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            digest = "b" * 64
            stale = "stale_requires_rerun"
            manifest_value = {
                "apple_device": {
                    "current_source_status": stale,
                    "current_proof_path": "artifact/device/proof.json",
                    "current_proof_sha256": digest,
                    "matrix_source_status": stale,
                    "matrix_proof_path": "artifact/device/matrix.json",
                    "matrix_proof_sha256": digest,
                },
                "android_aar": {
                    "current_source_status": stale,
                    "aar_path": proof_manifest.ANDROID_AAR_PATH,
                    "aar_sha256": digest,
                    "manifest_path": proof_manifest.ANDROID_AAR_MANIFEST_PATH,
                    "manifest_sha256": digest,
                },
                "android_device_runtime": {
                    "current_source_status": stale,
                    "proof_path": "target/android/canonical.json",
                    "proof_sha256": digest,
                },
                "android_physical_runtime": {
                    "current_source_status": stale,
                    "proof_path": "target/android/physical.json",
                    "proof_sha256": digest,
                },
                "local_release_index": {
                    "current_source_status": stale,
                    "index_path": "target/release/index.json",
                    "index_sha256": digest,
                    "consumer_receipt_path": "target/release/receipt.json",
                    "consumer_receipt_sha256": digest,
                },
                "performance": {
                    "current_source_status": stale,
                    "proof_path": "target/performance/proof.json",
                    "proof_sha256": digest,
                },
                "rust_publish": {
                    "current_source_status": stale,
                    "transcript_path": "target/legacy/rust-package-contract.log",
                    "transcript_sha256": digest,
                },
            }
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(manifest_value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            for binding in proof_manifest.BINDINGS:
                with self.subTest(binding=binding), self.assertRaisesRegex(
                    ProofManifestError,
                    rf"manifest-bound {binding} selection requires current status",
                ):
                    proof_manifest.resolve_bound_file_declaration(
                        root,
                        manifest,
                        binding=binding,
                    )

    def make_fixture(self, root: pathlib.Path) -> pathlib.Path:
        proof = root / "proofs" / "selected.json"
        proof.parent.mkdir()
        proof.write_bytes(b'{"status":"pass"}\n')
        digest = hashlib.sha256(proof.read_bytes()).hexdigest()
        artifact = root / "artifact"
        artifact.mkdir()
        (artifact / "results.json").write_text(
            json.dumps(
                self.performance_manifest("proofs/selected.json", digest),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return proof

    def test_bound_snapshot_uses_manifest_path_hash_and_same_proof_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            snapshot = select_bound_json_snapshot(
                root,
                manifest,
                binding="performance",
                selected_path=proof,
                label="performance proof",
            )
            proof.write_text('{"status":"replaced"}\n', encoding="utf-8")
            self.assertEqual(snapshot.value, {"status": "pass"})
            self.assertEqual(
                snapshot.file.sha256,
                manifest.value["performance"]["proof_sha256"],
            )

    def test_startup_manifest_digest_is_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            self.make_fixture(root)
            manifest_path = root / "artifact" / "results.json"
            snapshot = load_results_manifest_snapshot(manifest_path)
            load_results_manifest_snapshot(
                manifest_path, expected_sha256=snapshot.file.sha256
            )
            with self.assertRaisesRegex(ProofManifestError, "manifest changed"):
                load_results_manifest_snapshot(
                    manifest_path, expected_sha256="0" * 64
                )

    def test_different_selected_path_fails_even_with_identical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            other = proof.with_name("other.json")
            other.write_bytes(proof.read_bytes())
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            with self.assertRaisesRegex(ProofManifestError, "differs from results manifest"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=other,
                    label="performance proof",
                )

    def test_selected_path_rejects_a_noncanonical_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            alias = proof.parent / "nonexistent" / ".." / proof.name
            with self.assertRaisesRegex(ProofManifestError, "canonically spelled"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=alias,
                    label="performance proof",
                )

    def test_hash_mismatch_and_duplicate_manifest_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            manifest_path = root / "artifact" / "results.json"
            manifest_path.write_text(
                json.dumps(
                    self.performance_manifest(
                        "proofs/selected.json",
                        "0" * 64,
                    ),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            with self.assertRaisesRegex(ProofManifestError, "hash differs"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proof,
                    label="performance proof",
                )

            manifest_path.write_text(
                '{"performance":{},"performance":{}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ProofManifestError, "duplicate JSON key"):
                load_results_manifest_snapshot(manifest_path)
            manifest_path.write_text('{"ignored":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(ProofManifestError, "non-finite JSON number"):
                load_results_manifest_snapshot(manifest_path)

    def test_noncanonical_manifest_paths_and_proof_symlinks_fail(self) -> None:
        for relative in (
            "/absolute/proof.json",
            "../proof.json",
            "proofs//selected.json",
            "proofs\\selected.json",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                proof = self.make_fixture(root)
                digest = hashlib.sha256(proof.read_bytes()).hexdigest()
                (root / "artifact" / "results.json").write_text(
                    json.dumps(
                        self.performance_manifest(relative, digest),
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ProofManifestError):
                    manifest = load_results_manifest_snapshot(
                        root / "artifact" / "results.json"
                    )
                    select_bound_json_snapshot(
                        root,
                        manifest,
                        binding="performance",
                        selected_path=proof,
                        label="performance proof",
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            proof = self.make_fixture(root)
            target = proof.with_name("target.json")
            proof.rename(target)
            proof.symlink_to(target)
            manifest = load_results_manifest_snapshot(root / "artifact" / "results.json")
            with self.assertRaises(ProofManifestError):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proof,
                    label="performance proof",
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            external_proof = outside / "selected.json"
            external_proof.write_bytes(b'{"status":"pass"}\n')
            proofs = root / "proofs"
            proofs.mkdir()
            (proofs / "external").symlink_to(outside, target_is_directory=True)
            artifact = root / "artifact"
            artifact.mkdir()
            digest = hashlib.sha256(external_proof.read_bytes()).hexdigest()
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(
                    self.performance_manifest(
                        "proofs/external/selected.json",
                        digest,
                    ),
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = load_results_manifest_snapshot(manifest_path)
            with self.assertRaisesRegex(ProofManifestError, "cannot safely open"):
                select_bound_json_snapshot(
                    root,
                    manifest,
                    binding="performance",
                    selected_path=proofs / "external" / "selected.json",
                    label="performance proof",
                )


if __name__ == "__main__":
    unittest.main()
