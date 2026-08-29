from __future__ import annotations

import contextlib
import copy
import dataclasses
import hashlib
import inspect
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from collections.abc import Callable
from typing import Any, cast
from unittest import mock

import apple_publication_contract
import crates_io_publication_contract
import platform_publication_contract
import release_publication_contract as publication_contract
import source_results_assembler as assembler
import rust_package_handoff
from git_provenance import GitProvenanceError
from test_release_publication_contract import frozen_baseline_manifest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_COMMIT = "a" * 40
RESULTS_COMMIT = "b" * 40
SOURCE_DIGEST = "c" * 64
RESULTS_DIGEST = "d" * 64
ANDROID_RUN = "1" * 32
CONSUMER_RUN = "3" * 32
RUST_HANDOFF_PATH = (
    "target/qperiapt-rust-package-handoffs/"
    f"transaction.1-{'4' * 32}/rust-package-handoff.json"
)
RUST_HANDOFF_SHA256 = "5" * 64


def _live_results() -> dict[str, Any]:
    return json.loads(
        (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
    )


def _proof_inputs(*, installed: bool) -> dict[str, str]:
    excluded = (
        frozenset()
        if installed
        else assembler.INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS
    )
    return {
        key: hashlib.sha256(relative.encode("utf-8")).hexdigest()
        for key, relative in assembler.PROOF_TO_BYTE_INPUT_PATHS.items()
        if key not in excluded
    }


def _initial_baseline() -> dict[str, Any]:
    baseline = frozen_baseline_manifest()
    baseline["proof_to_byte_inputs"] = _proof_inputs(installed=False)
    baseline.pop("android_physical_runtime", None)
    # Restore the frozen 0.1.4-opening publication state: exactly the
    # five frozen historical leaves (dropping any active v0.1.4 cohort
    # state) with the selector activated on the frozen published
    # apple_v0_1_3 receipt.
    publications = baseline["release_publications"]
    baseline["release_publications"] = {
        key: publications[key]
        for key in (
            apple_publication_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
            platform_publication_contract.PLATFORM_R2_PUBLICATION_KEY,
            apple_publication_contract.APPLE_V0_1_3_PUBLICATION_KEY,
            platform_publication_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
            crates_io_publication_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
        )
    }
    swift = baseline["swift_xcframework"]
    swift["active_publication_key"] = (
        apple_publication_contract.APPLE_V0_1_3_PUBLICATION_KEY
    )
    swift["distribution"] = (
        apple_publication_contract.frozen_v0_1_3_distribution()
    )
    return baseline


def _exact_section(fields: frozenset[str], label: str) -> dict[str, object]:
    return {field: f"{label}:{field}" for field in fields}


def _plan_current(previous: dict[str, Any]) -> dict[str, Any]:
    current = copy.deepcopy(previous)
    current["proof_source_tree_sha256"] = SOURCE_DIGEST
    current["proof_to_byte_inputs"] = _proof_inputs(installed=True)
    current["provenance"]["snapshot_commit"] = SOURCE_COMMIT
    current["android_aar"] = _exact_section(
        assembler.ANDROID_AAR_SECTION_FIELDS,
        "aar",
    )
    current["android_device_runtime"] = _exact_section(
        assembler.ANDROID_RUNTIME_SECTION_FIELDS,
        "android",
    )
    current["apple_device"] = assembler._stale_optional_section(
        previous,
        "apple_device",
        ("current_source_status", "matrix_source_status"),
    )
    current["local_release_index"] = _exact_section(
        assembler.LOCAL_INDEX_SECTION_FIELDS,
        "index",
    )
    current["rust_publish"] = _exact_section(
        assembler.RUST_PACKAGE_CURRENT_SECTION_FIELDS,
        "rust",
    )
    current["performance"] = assembler._stale_optional_section(
        previous,
        "performance",
        ("current_source_status",),
    )
    # The retired one-time selector migration has no successor: assembly
    # carries the previous selector byte-for-byte.
    current["swift_xcframework"] = copy.deepcopy(previous["swift_xcframework"])
    return current


def _domain_projection_fixture() -> tuple[
    dict[str, object], assembler.VerifiedSourceDomains
]:
    current: dict[str, object] = {
        "rust_publish": {"domain": "rust"},
        "android_aar": {"domain": "aar"},
        "android_device_runtime": {"domain": "android"},
        "local_release_index": {"domain": "index"},
    }
    verified = assembler.VerifiedSourceDomains(
        rust_section=copy.deepcopy(current["rust_publish"]),
        rust_handoff=mock.Mock(),
        aar_section=copy.deepcopy(current["android_aar"]),
        android=mock.Mock(section=copy.deepcopy(current["android_device_runtime"])),
        index=mock.Mock(section=copy.deepcopy(current["local_release_index"])),
        pins=(),
    )
    return current, verified


class SourceResultsAssemblerTests(unittest.TestCase):
    def test_finalize_cli_requires_the_core_publication_selectors(self) -> None:
        command = [
            "finalize",
            "a" * 64,
            "--rust-handoff-manifest",
            RUST_HANDOFF_PATH,
            "--rust-handoff-sha256",
            RUST_HANDOFF_SHA256,
            "--android-runtime-run",
            ANDROID_RUN,
            "--consumer-run",
            CONSUMER_RUN,
        ]
        arguments = assembler._parser().parse_args(command)
        self.assertEqual(RUST_HANDOFF_PATH, arguments.rust_handoff_manifest)
        self.assertEqual(RUST_HANDOFF_SHA256, arguments.rust_handoff_sha256)
        self.assertEqual(ANDROID_RUN, arguments.android_runtime_run)
        self.assertEqual(CONSUMER_RUN, arguments.consumer_run)
        required_flags = (
            "--rust-handoff-manifest",
            "--rust-handoff-sha256",
            "--android-runtime-run",
            "--consumer-run",
        )
        for omitted in required_flags:
            incomplete = list(command)
            index = incomplete.index(omitted)
            del incomplete[index : index + 2]
            with (
                self.subTest(omitted=omitted),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                assembler._parser().parse_args(incomplete)

    def test_internal_apis_exclude_product_readiness_selectors(self) -> None:
        selector_fields = assembler.SourceEvidenceSelectors.__dataclass_fields__
        for name in (
            "apple_matrix_run",
            "android_physical_run",
            "performance_proof",
        ):
            with self.subTest(dataclass_field=name):
                self.assertNotIn(name, selector_fields)

        for function in (
            assembler._assemble_source_results,
            assembler.assemble_source_results,
            assembler.finalize_source_results,
        ):
            parameters = inspect.signature(function).parameters
            for name in (
                "apple_matrix_run",
                "android_physical_run",
                "performance_proof",
            ):
                with self.subTest(function=function.__name__, parameter=name):
                    self.assertNotIn(name, parameters)

    def test_runbooks_keep_product_readiness_outside_the_core_successor(self) -> None:
        documents = {
            "artifact": (ROOT / "ARTIFACT.md").read_text(encoding="utf-8"),
            "stable notes": (
                ROOT / "artifact" / "stable-release-notes.md"
            ).read_text(encoding="utf-8"),
            "embedding": (
                ROOT / "docs" / "EMBEDDING_READINESS.md"
            ).read_text(encoding="utf-8"),
            "android": (
                ROOT / "bindings" / "android" / "README.md"
            ).read_text(encoding="utf-8"),
        }
        normalized = {
            label: " ".join(value.split()) for label, value in documents.items()
        }
        combined = " ".join(normalized.values())
        for obsolete in (
            "--apple-matrix-run",
            "--android-physical-run",
            "--performance-proof",
            "selected by the same evidence successor",
            "select it under `android_physical_runtime` in that successor",
        ):
            with self.subTest(obsolete=obsolete):
                self.assertNotIn(obsolete, combined)
        self.assertIn(
            "The stable package-publication assembler does not select that proof",
            normalized["artifact"],
        )
        self.assertIn(
            "separate product-readiness selectors",
            normalized["stable notes"],
        )
        self.assertIn(
            "separately reviewed product-readiness evidence transition",
            normalized["embedding"],
        )
        self.assertIn(
            "Stable package publication leaves this selector absent",
            normalized["android"],
        )
        stable_index_pins = (
            "QPERIAPT_RELEASE_INDEX_CHANNEL=release",
            "QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=0",
            "QPERIAPT_RELEASE_INDEX_INCLUDE_APPLE_MATRIX=0",
            "QPERIAPT_RELEASE_INDEX_INCLUDE_ANDROID_RUNTIME=1",
        )
        for label in ("artifact", "embedding", "android"):
            for pin in stable_index_pins:
                with self.subTest(document=label, index_pin=pin):
                    self.assertIn(pin, normalized[label])

    def test_run_ids_require_exact_lowercase_hex(self) -> None:
        valid = "0123456789abcdef" * 2
        self.assertEqual(valid, assembler._run_id(valid, "run"))
        for value in (
            "a" * 31,
            "a" * 33,
            "A" * 32,
            "g" * 32,
            "１２" * 16,
            32,
        ):
            with self.subTest(invalid=value), self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "32 lowercase hexadecimal",
            ):
                assembler._run_id(cast(str, value), "run")

    def test_android_projection_requires_canonical_release_emulator(self) -> None:
        proof = {
            "android": {"build_tools": "36.0.0"},
            "device": {
                "abi": "arm64-v8a",
                "kind": "emulator",
                "page_size": 16_384,
                "sdk": 35,
            },
            "generated_at": "2026-08-15T00:00:00Z",
            "git_commit": SOURCE_COMMIT,
            "proof_source_tree_sha256": SOURCE_DIGEST,
            "release_candidate_mode": True,
            "result": {
                "passed_tests": list(assembler.ANDROID_EXPECTED_TESTS),
                "status": "pass",
            },
            "schema": assembler.ANDROID_DEVICE_PROOF_SCHEMA_VERSION,
            "source_tree_dirty": False,
        }
        snapshot = mock.Mock(value=proof, file=mock.Mock(sha256="6" * 64))
        proof_paths = mock.Mock()
        with (
            mock.patch.object(
                assembler,
                "load_json_object_snapshot",
                return_value=snapshot,
            ),
            mock.patch.object(
                assembler.android_device_proof,
                "verify_proof_schema",
            ),
            mock.patch.object(
                assembler.android_device_proof,
                "verify_proof_freshness",
            ),
            mock.patch.object(
                assembler.android_device_proof,
                "proof_paths",
                return_value=proof_paths,
            ),
            mock.patch.object(
                assembler.android_device_proof,
                "validate_selected_run_layout",
            ),
            mock.patch.object(
                assembler.android_device_proof,
                "verify_proof_contents",
            ) as verify_contents,
        ):
            projection = assembler._android_projection(
                ANDROID_RUN,
                assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST),
            )

        self.assertEqual("arm64-v8a", projection.section["device_abi"])
        self.assertIs(True, projection.section["release_candidate_mode"])
        verify_contents.assert_called_once_with(
            assembler.REPOSITORY_ROOT,
            proof,
            proof_paths,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=16_384,
            expected_device_sdk=35,
            require_release_mode=True,
            allow_dirty_proof=False,
        )

    def test_core_index_accepts_only_the_android_runtime_summary(self) -> None:
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        android_sha256 = "6" * 64
        aar_sha256 = "7" * 64
        index_sha256 = "8" * 64
        receipt_sha256 = "9" * 64
        android = assembler.AndroidProjection(
            snapshot=mock.Mock(file=mock.Mock(sha256=android_sha256)),
            section={"run_id": ANDROID_RUN},
        )
        index_value = {
            "channel": "release",
            "diagnostic_only": False,
            "generated_at": "2026-08-25T00:00:00Z",
            "git": {"commit": SOURCE_COMMIT, "source_tree_dirty": False},
            "proof_summaries": {
                "android_runtime": {"sha256": android_sha256}
            },
            "schema_version": assembler.LOCAL_RELEASE_INDEX_SCHEMA_VERSION,
        }
        verified = mock.Mock(
            path=assembler._index_path(source),
            sha256=index_sha256,
            value=index_value,
        )
        receipt = mock.Mock(
            value={"generated_at": "2026-08-25T00:01:00Z", "status": "pass"},
            file=mock.Mock(sha256=receipt_sha256),
        )
        archive = mock.Mock()
        with (
            mock.patch.object(
                assembler.release_index,
                "verify_release_index_snapshot",
                return_value=verified,
            ),
            mock.patch.object(
                assembler,
                "read_regular_snapshot",
                return_value=mock.Mock(sha256=index_sha256),
            ),
            mock.patch.object(
                assembler.release_consumer_smoke,
                "android_runtime_summary_identity",
                return_value=(ANDROID_RUN, android_sha256),
            ),
            mock.patch.object(
                assembler.release_consumer_smoke,
                "indexed_android_aar_sha256",
                return_value=aar_sha256,
            ),
            mock.patch.object(
                assembler.release_consumer_smoke,
                "load_private_consumer_receipt",
                return_value=receipt,
            ),
            mock.patch.object(
                assembler.release_consumer_smoke,
                "c_archive_entries",
                return_value=[archive],
            ),
            mock.patch.object(
                assembler.release_consumer_smoke,
                "validate_consumer_receipt",
            ) as validate_receipt,
        ):
            projection = assembler._index_projection(
                source,
                CONSUMER_RUN,
                android,
                {"aar_sha256": aar_sha256},
            )

        self.assertEqual(index_sha256, projection.section["index_sha256"])
        self.assertEqual(receipt_sha256, projection.section["consumer_receipt_sha256"])
        validate_receipt.assert_called_once()

        with (
            mock.patch.object(
                assembler.release_index,
                "verify_release_index_snapshot",
                return_value=mock.Mock(
                    path=verified.path,
                    sha256=index_sha256,
                    value={
                        **index_value,
                        "proof_summaries": {
                            **index_value["proof_summaries"],
                            "apple_matrix": {"sha256": "a" * 64},
                        },
                    },
                ),
            ),
            mock.patch.object(
                assembler,
                "read_regular_snapshot",
                return_value=mock.Mock(sha256=index_sha256),
            ),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "exactly the Android runtime summary",
            ),
        ):
            assembler._index_projection(
                source,
                CONSUMER_RUN,
                android,
                {"aar_sha256": aar_sha256},
            )

    def test_initial_and_installed_proof_maps_are_exactly_distinct(self) -> None:
        initial = _initial_baseline()
        installed = copy.deepcopy(initial)
        installed["proof_to_byte_inputs"] = _proof_inputs(installed=True)

        self.assertEqual(237, len(assembler.PROOF_TO_BYTE_INPUT_PATHS))
        self.assertEqual(47, len(assembler.INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS))
        self.assertEqual(190, len(initial["proof_to_byte_inputs"]))
        self.assertEqual(237, len(installed["proof_to_byte_inputs"]))
        self.assertEqual(
            set(assembler.INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS),
            set(installed["proof_to_byte_inputs"])
            - set(initial["proof_to_byte_inputs"]),
        )

        assembler._validate_baseline_document_shape(initial, require_initial=True)
        assembler._validate_baseline_document_shape(installed, require_initial=False)
        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "installed source successor",
        ):
            assembler._validate_baseline_document_shape(
                initial,
                require_initial=False,
            )
        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "one-time proof-input migration",
        ):
            assembler._validate_baseline_document_shape(
                installed,
                require_initial=True,
            )

        incomplete = copy.deepcopy(initial)
        incomplete["proof_to_byte_inputs"].pop(next(iter(incomplete["proof_to_byte_inputs"])))
        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "one-time proof-input migration",
        ):
            assembler._validate_baseline_document_shape(
                incomplete,
                require_initial=True,
            )

    def test_live_results_is_the_exact_initial_migration_baseline(self) -> None:
        baseline = _live_results()
        inputs = baseline["proof_to_byte_inputs"]
        current_keys = set(assembler.PROOF_TO_BYTE_INPUT_PATHS)
        live_sha256 = hashlib.sha256(
            (ROOT / "artifact/results.json").read_bytes()
        ).hexdigest()

        if set(inputs) == current_keys:
            # Installed successor state (source_ci_gate's installed dispatch).
            self.assertEqual(237, len(inputs))
            self.assertNotEqual(assembler.INITIAL_RESULTS_SHA256, live_sha256)
            for key, digest in inputs.items():
                self.assertTrue(key.endswith("_sha256"), key)
                self.assertIsNotNone(
                    assembler.SHA256_RE.fullmatch(digest), key
                )
            state = publication_contract.publication_state(baseline)
            publications = baseline["release_publications"]
            # The frozen five-leaf historical floor is permanent in every
            # committed manifest on the 0.1.4 line.
            for key in (
                apple_publication_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
                platform_publication_contract.PLATFORM_R2_PUBLICATION_KEY,
                apple_publication_contract.APPLE_V0_1_3_PUBLICATION_KEY,
                platform_publication_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
                crates_io_publication_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
            ):
                self.assertIn(key, publications)
            if state == publication_contract.PUBLICATION_STATE_SOURCE:
                # Live source manifest: exactly the five frozen leaves
                # with the apple_v0_1_3 selector active — the assembler's
                # own installed baseline shape (this holds for the current
                # live bytes, whose selector activated on the published
                # 0.1.3 line and whose v0.1.4 cohort has not recorded).
                self.assertEqual(
                    apple_publication_contract.APPLE_V0_1_3_PUBLICATION_KEY,
                    baseline["swift_xcframework"]["active_publication_key"],
                )
                assembler._validate_baseline_document_shape(
                    baseline,
                    require_initial=False,
                )
                with self.assertRaisesRegex(
                    assembler.SourceResultsAssemblerError,
                    "one-time proof-input migration",
                ):
                    assembler._validate_baseline_document_shape(
                        baseline,
                        require_initial=True,
                    )
                if (
                    baseline["android_aar"]["aar_path"]
                    == assembler.ANDROID_AAR_PATH
                ):
                    # Fresh 0.1.4-line installed successor: its declared
                    # package currentness holds against the 0.1.4 path
                    # authorities.
                    assembler.validate_declared_currentness(baseline)
                else:
                    # The 0.1.3-line verified manifest is still installed
                    # ahead of the stage-5 baseline swap: its sections
                    # declare the previous line's currentness, which the
                    # 0.1.4 path authorities reject wholesale (the crafted
                    # initial baseline deliberately skips this validator).
                    with self.assertRaises(assembler.ProofManifestError):
                        assembler.validate_declared_currentness(baseline)
                return
            # Receipt-finalized stable manifest: the recorded v0.1.4
            # cohort state is not the assembler's five-leaf baseline, so
            # both shape modes must fail closed.
            self.assertIn(
                state,
                (
                    publication_contract.PUBLICATION_STATE_PENDING,
                    publication_contract.PUBLICATION_STATE_VERIFIED,
                ),
            )
            assembler.validate_declared_currentness(baseline)
            publication_contract.validate_stable_source_currentness(baseline)
            expected_active = (
                apple_publication_contract.APPLE_V0_1_4_PUBLICATION_KEY
                if state == publication_contract.PUBLICATION_STATE_VERIFIED
                else apple_publication_contract.APPLE_V0_1_3_PUBLICATION_KEY
            )
            self.assertEqual(
                expected_active,
                baseline["swift_xcframework"]["active_publication_key"],
            )
            for require_initial in (True, False):
                with self.subTest(
                    require_initial=require_initial
                ), self.assertRaisesRegex(
                    assembler.SourceResultsAssemblerError,
                    "five frozen historical leaves",
                ):
                    assembler._validate_baseline_document_shape(
                        baseline,
                        require_initial=require_initial,
                    )
            return

        # Frozen initial baseline state (source_ci_gate's initial dispatch;
        # this branch selects only after the stage-5 opening installs the
        # crafted 190-key baseline and repins INITIAL_RESULTS_SHA256).
        self.assertEqual(assembler.INITIAL_RESULTS_SHA256, live_sha256)
        self.assertEqual(190, len(inputs))
        self.assertEqual(
            set(assembler.INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS),
            current_keys - set(inputs),
        )
        assembler._validate_baseline_document_shape(
            baseline,
            require_initial=True,
        )
        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "installed source successor",
        ):
            assembler._validate_baseline_document_shape(
                baseline,
                require_initial=False,
            )

    def test_source_ci_gate_dispatches_only_exact_initial_or_installed(self) -> None:
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        authority = _proof_inputs(installed=True)
        for mode, baseline in (
            ("initial", _initial_baseline()),
            (
                "installed",
                {
                    **_initial_baseline(),
                    "proof_to_byte_inputs": copy.deepcopy(authority),
                },
            ),
        ):
            with (
                self.subTest(mode=mode),
                mock.patch.object(
                    assembler,
                    "_load_pinned_baseline",
                    return_value=baseline,
                ),
                mock.patch.object(
                    assembler,
                    "_source_identity",
                    return_value=source,
                ) as identity,
                mock.patch.object(assembler, "validate_baseline") as validate,
                mock.patch.object(
                    assembler,
                    "capture_proof_input_digests",
                    return_value=authority,
                ) as capture,
            ):
                observed_mode, observed_source = assembler.source_ci_gate(
                    RESULTS_DIGEST,
                    SOURCE_COMMIT,
                )

            self.assertEqual(mode, observed_mode)
            self.assertEqual(source, observed_source)
            self.assertEqual(2, identity.call_count)
            if mode == "initial":
                self.assertEqual(2, validate.call_count)
                self.assertEqual(3, capture.call_count)
            else:
                validate.assert_not_called()
                capture.assert_not_called()

    def test_source_ci_gate_rejects_malformed_mixed_and_wrong_delta_states(
        self,
    ) -> None:
        initial = _initial_baseline()
        installed = copy.deepcopy(initial)
        installed["proof_to_byte_inputs"] = _proof_inputs(installed=True)
        mixed = copy.deepcopy(initial)
        added = next(iter(assembler.INITIAL_BASELINE_MISSING_PROOF_INPUT_KEYS))
        mixed["proof_to_byte_inputs"][added] = "e" * 64
        wrong_delta = copy.deepcopy(initial)
        removed = next(iter(wrong_delta["proof_to_byte_inputs"]))
        wrong_delta["proof_to_byte_inputs"].pop(removed)
        wrong_delta["proof_to_byte_inputs"][added] = "e" * 64
        malformed = copy.deepcopy(installed)
        malformed["proof_to_byte_inputs"][next(iter(malformed["proof_to_byte_inputs"]))] = (
            "not-a-digest"
        )
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)

        for label, baseline in (
            ("mixed", mixed),
            ("wrong-190-delta", wrong_delta),
            ("malformed-installed", malformed),
        ):
            with (
                self.subTest(label=label),
                mock.patch.object(
                    assembler,
                    "_load_pinned_baseline",
                    return_value=baseline,
                ),
                mock.patch.object(
                    assembler,
                    "_source_identity",
                    return_value=source,
                ),
                self.assertRaises(assembler.SourceResultsAssemblerError),
            ):
                assembler.source_ci_gate(RESULTS_DIGEST, SOURCE_COMMIT)

        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "expected CI source commit is malformed",
        ):
            assembler.source_ci_gate(RESULTS_DIGEST, "not-a-commit")

    def test_source_ci_initial_readiness_rejects_changed_dirty_or_wrong_commit(
        self,
    ) -> None:
        initial = _initial_baseline()
        authority = _proof_inputs(installed=True)
        changed = copy.deepcopy(authority)
        changed[next(iter(changed))] = "f" * 64
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)

        with (
            mock.patch.object(
                assembler,
                "_load_pinned_baseline",
                return_value=initial,
            ),
            mock.patch.object(assembler, "_source_identity", return_value=source),
            mock.patch.object(assembler, "validate_baseline"),
            mock.patch.object(
                assembler,
                "capture_proof_input_digests",
                side_effect=(authority, changed),
            ),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "authority changed during readiness",
            ),
        ):
            assembler.source_ci_gate(RESULTS_DIGEST, SOURCE_COMMIT)

        for label, identity in (
            (
                "dirty",
                assembler.SourceResultsAssemblerError("dirty source fixture"),
            ),
            (
                "wrong-commit",
                assembler.SourceIdentity("9" * 40, SOURCE_DIGEST),
            ),
        ):
            with (
                self.subTest(label=label),
                mock.patch.object(
                    assembler,
                    "_load_pinned_baseline",
                    return_value=initial,
                ),
                mock.patch.object(
                    assembler,
                    "_source_identity",
                    side_effect=identity if isinstance(identity, Exception) else None,
                    return_value=None if isinstance(identity, Exception) else identity,
                ),
                self.assertRaises(assembler.SourceResultsAssemblerError),
            ):
                assembler.source_ci_gate(RESULTS_DIGEST, SOURCE_COMMIT)

    def test_source_ci_final_baseline_recheck_closes_input_and_source_races(
        self,
    ) -> None:
        initial = _initial_baseline()
        authority = _proof_inputs(installed=True)
        changed_authority = copy.deepcopy(authority)
        changed_authority[next(iter(changed_authority))] = "f" * 64
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        changed_source = assembler.SourceIdentity(SOURCE_COMMIT, "9" * 64)

        for race in ("input", "source"):
            state = {"closed_baseline": False, "validations": 0}

            def validate(*_args: object, **_kwargs: object) -> dict[str, Any]:
                state["validations"] += 1
                if state["validations"] == 2:
                    state["closed_baseline"] = True
                return initial

            def capture(_root: pathlib.Path) -> dict[str, str]:
                if race == "input" and state["closed_baseline"]:
                    return changed_authority
                return authority

            def identity() -> assembler.SourceIdentity:
                if race == "source" and state["closed_baseline"]:
                    return changed_source
                return source

            with (
                self.subTest(race=race),
                mock.patch.object(
                    assembler,
                    "_load_pinned_baseline",
                    return_value=initial,
                ),
                mock.patch.object(assembler, "validate_baseline", validate),
                mock.patch.object(
                    assembler,
                    "capture_proof_input_digests",
                    capture,
                ),
                mock.patch.object(assembler, "_source_identity", identity),
                self.assertRaises(assembler.SourceResultsAssemblerError),
            ):
                assembler.source_ci_gate(RESULTS_DIGEST, SOURCE_COMMIT)

    def test_source_ci_cli_never_labels_installed_dispatch_as_readiness(self) -> None:
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        for mode, expected_marker in (
            ("initial", "SOURCE_TRANSITION_READINESS_PASS mode=initial"),
            ("installed", "SOURCE_CI_GATE_MODE mode=installed"),
        ):
            output = io.StringIO()
            args = mock.Mock(
                command="ci-source-gate",
                expected_results_sha256=RESULTS_DIGEST,
                expected_commit=SOURCE_COMMIT,
            )
            with (
                mock.patch.object(
                    assembler,
                    "source_ci_gate",
                    return_value=(mode, source),
                ),
                contextlib.redirect_stdout(output),
            ):
                assembler.run(args)
            self.assertTrue(output.getvalue().startswith(expected_marker))
            if mode == "installed":
                self.assertNotIn("READINESS_PASS", output.getvalue())

    def test_validate_baseline_pins_worktree_bytes_to_head_and_mode(self) -> None:
        for require_initial in (True, False):
            with self.subTest(require_initial=require_initial):
                document = _initial_baseline()
                if not require_initial:
                    document["proof_to_byte_inputs"] = _proof_inputs(installed=True)
                payload = assembler.canonical_json_bytes(document)
                digest = hashlib.sha256(payload).hexdigest()
                with tempfile.TemporaryDirectory() as temporary:
                    path = pathlib.Path(temporary).resolve() / "results.json"
                    path.write_bytes(payload)
                    os.chmod(path, assembler.PUBLIC_FILE_MODE)
                    release_validator = mock.Mock()
                    currentness_validator = mock.Mock()
                    with (
                        mock.patch.object(assembler, "RESULTS_PATH", path),
                        mock.patch.object(
                            assembler,
                            "INITIAL_RESULTS_SHA256",
                            digest,
                        ),
                        mock.patch.object(
                            assembler,
                            "_load_head_results_bytes",
                            return_value=payload,
                        ) as load_head,
                        mock.patch.object(
                            assembler,
                            "validate_release_publications",
                            release_validator,
                        ),
                        mock.patch.object(
                            assembler,
                            "validate_declared_currentness",
                            currentness_validator,
                        ),
                    ):
                        self.assertEqual(
                            document,
                            assembler.validate_baseline(
                                digest,
                                require_initial=require_initial,
                            ),
                        )
                    load_head.assert_called_once_with()
                    if require_initial:
                        release_validator.assert_called_once_with(document)
                        currentness_validator.assert_not_called()
                    else:
                        currentness_validator.assert_called_once_with(document)
                        release_validator.assert_not_called()

    def test_validate_baseline_rejects_nonidentical_head_blob(self) -> None:
        document = _initial_baseline()
        payload = assembler.canonical_json_bytes(document)
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary).resolve() / "results.json"
            path.write_bytes(payload)
            os.chmod(path, assembler.PUBLIC_FILE_MODE)
            with (
                mock.patch.object(assembler, "RESULTS_PATH", path),
                mock.patch.object(
                    assembler,
                    "INITIAL_RESULTS_SHA256",
                    digest,
                ),
                mock.patch.object(
                    assembler,
                    "_load_head_results_bytes",
                    return_value=payload + b"\n",
                ),
                self.assertRaisesRegex(
                    assembler.SourceResultsAssemblerError,
                    "not byte-identical to HEAD",
                ),
            ):
                assembler.validate_baseline(digest)

    def test_initial_baseline_rejects_same_shape_committed_byte_change(self) -> None:
        document = _initial_baseline()
        document["generated_at"] = "2026-08-15T00:00:00Z"
        payload = assembler.canonical_json_bytes(document)
        digest = hashlib.sha256(payload).hexdigest()
        self.assertNotEqual(assembler.INITIAL_RESULTS_SHA256, digest)
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary).resolve() / "results.json"
            path.write_bytes(payload)
            os.chmod(path, assembler.PUBLIC_FILE_MODE)
            with (
                mock.patch.object(assembler, "RESULTS_PATH", path),
                mock.patch.object(
                    assembler,
                    "_load_head_results_bytes",
                    return_value=payload,
                ),
                self.assertRaisesRegex(
                    assembler.SourceResultsAssemblerError,
                    "frozen byte authority",
                ),
            ):
                assembler.validate_baseline(digest, require_initial=True)

    def test_source_ci_wrong_frozen_initial_digest_fails_before_source_sampling(
        self,
    ) -> None:
        initial = _initial_baseline()
        identity = mock.Mock()
        capture = mock.Mock()
        with (
            mock.patch.object(
                assembler,
                "_load_pinned_baseline",
                return_value=initial,
            ),
            mock.patch.object(
                assembler,
                "validate_baseline",
                side_effect=assembler.SourceResultsAssemblerError(
                    "initial source successor baseline differs from the frozen byte authority"
                ),
            ),
            mock.patch.object(assembler, "_source_identity", identity),
            mock.patch.object(
                assembler,
                "capture_proof_input_digests",
                capture,
            ),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "frozen byte authority",
            ),
        ):
            assembler.source_ci_gate("e" * 64, SOURCE_COMMIT)
        identity.assert_not_called()
        capture.assert_not_called()

    def test_installed_selectors_bind_paths_to_run_identities(self) -> None:
        current: dict[str, object] = {
            "rust_publish": {
                "handoff_manifest_path": RUST_HANDOFF_PATH,
                "handoff_manifest_sha256": RUST_HANDOFF_SHA256,
            },
            "android_device_runtime": {
                "run_id": ANDROID_RUN,
                "proof_path": assembler._relative(
                    assembler._android_proof_path(ANDROID_RUN)
                ),
            },
            "local_release_index": {
                "consumer_receipt_run_id": CONSUMER_RUN,
                "consumer_receipt_path": assembler._relative(
                    assembler.CONSUMER_RECEIPTS_ROOT
                    / CONSUMER_RUN
                    / assembler.release_consumer_smoke.CONSUMER_RECEIPT_LEAF
                ),
            },
        }
        self.assertEqual(
            assembler.SourceEvidenceSelectors(
                rust_handoff_manifest=RUST_HANDOFF_PATH,
                rust_handoff_sha256=RUST_HANDOFF_SHA256,
                android_runtime_run=ANDROID_RUN,
                consumer_run=CONSUMER_RUN,
            ),
            assembler._installed_selectors(current),
        )

        mismatched = copy.deepcopy(current)
        mismatched["android_device_runtime"]["proof_path"] = "target/wrong.json"
        with self.assertRaisesRegex(
            assembler.SourceResultsAssemblerError,
            "proof path differs from its run identity",
        ):
            assembler._installed_selectors(mismatched)

    def test_assemble_document_marks_optional_evidence_stale(self) -> None:
        previous = _initial_baseline()
        original = copy.deepcopy(previous)
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        proof_inputs = _proof_inputs(installed=True)
        footprint = {"fixture": {"bytes": 1}}
        rust = _exact_section(assembler.RUST_PACKAGE_CURRENT_SECTION_FIELDS, "rust")
        aar = _exact_section(assembler.ANDROID_AAR_SECTION_FIELDS, "aar")
        android = _exact_section(assembler.ANDROID_RUNTIME_SECTION_FIELDS, "android")
        index = _exact_section(assembler.LOCAL_INDEX_SECTION_FIELDS, "index")
        with (
            mock.patch.object(assembler, "validate_declared_currentness"),
            mock.patch.object(
                assembler,
                "validate_stable_source_currentness",
            ) as stable_currentness,
            mock.patch.object(assembler, "validate_release_publications"),
            mock.patch.object(assembler, "validate_release_publication_transition"),
        ):
            current = assembler.assemble_source_results_document(
                previous,
                source=source,
                proof_inputs=proof_inputs,
                footprint=footprint,
                rust_section=rust,
                aar_section=aar,
                android_section=android,
                index_section=index,
            )

        stable_currentness.assert_called_once_with(current)

        self.assertEqual(original, previous)
        self.assertEqual(SOURCE_COMMIT, current["provenance"]["snapshot_commit"])
        self.assertEqual(SOURCE_DIGEST, current["proof_source_tree_sha256"])
        self.assertNotIn("android_physical_runtime", current)
        self.assertEqual(
            "stale_requires_rerun",
            current["apple_device"]["current_source_status"],
        )
        self.assertEqual(
            "stale_requires_rerun",
            current["apple_device"]["matrix_source_status"],
        )
        self.assertEqual(
            "stale_requires_rerun",
            current["performance"]["current_source_status"],
        )

        aar["aar_sha256"] = "mutated after assembly"
        self.assertNotEqual("mutated after assembly", current["android_aar"]["aar_sha256"])

    def test_mutation_plan_rejects_top_level_and_provenance_drift(self) -> None:
        previous = _initial_baseline()
        current = _plan_current(previous)
        assembler.plan_authorized_mutations(previous, current)

        cases: tuple[tuple[str, Callable[[dict[str, Any]], None], str], ...] = (
            (
                "added top level",
                lambda value: value.__setitem__("unexpected", {}),
                "added or removed an unauthorized top-level section",
            ),
            (
                "forbidden section",
                lambda value: value.__setitem__("purpose", "rewritten"),
                "changed forbidden section 'purpose'",
            ),
            (
                "provenance field set",
                lambda value: value["provenance"].__setitem__("unexpected", True),
                "changed provenance fields",
            ),
            (
                "provenance fact",
                lambda value: value["provenance"].__setitem__("note", "rewritten"),
                "changed forbidden provenance field 'note'",
            ),
        )
        for label, mutate, message in cases:
            with self.subTest(label=label):
                candidate = copy.deepcopy(current)
                mutate(candidate)
                with self.assertRaisesRegex(
                    assembler.SourceResultsAssemblerError,
                    message,
                ):
                    assembler.plan_authorized_mutations(previous, candidate)

    def test_mutation_plan_rejects_optional_evidence_promotion(self) -> None:
        previous = _initial_baseline()
        current = _plan_current(previous)
        assembler.plan_authorized_mutations(previous, current)

        cases = (
            (
                "apple device",
                lambda value: value["apple_device"].__setitem__(
                    "current_source_status", "current_clean_tree_physical_pass"
                ),
                "Apple evidence is not the deterministic stale projection",
            ),
            (
                "apple matrix",
                lambda value: value["apple_device"].__setitem__(
                    "matrix_source_status", "current_clean_tree_physical_pass"
                ),
                "Apple evidence is not the deterministic stale projection",
            ),
            (
                "performance",
                lambda value: value["performance"].__setitem__(
                    "current_source_status", "current_controlled_pass"
                ),
                "performance evidence is not the deterministic stale projection",
            ),
            (
                "physical Android",
                lambda value: value.__setitem__("android_physical_runtime", {}),
                "added or removed an unauthorized top-level section",
            ),
        )
        for label, mutate, message in cases:
            promoted = copy.deepcopy(current)
            mutate(promoted)
            with self.subTest(optional_domain=label), self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                message,
            ):
                assembler.plan_authorized_mutations(previous, promoted)

    def test_verified_domain_projections_match_all_sections(self) -> None:
        previous = {"fixture": "previous"}
        current, verified = _domain_projection_fixture()
        with mock.patch.object(assembler, "_validate_assembled_results") as validate:
            assembler._validate_verified_domain_projections(
                previous,
                current,
                verified=verified,
            )
        validate.assert_called_once_with(
            previous,
            current,
            android=verified.android,
        )

    def test_verified_domain_projection_mismatches_fail_closed(self) -> None:
        previous = {"fixture": "previous"}
        current, verified = _domain_projection_fixture()
        cases = (
            ("rust_publish", "Rust package projection"),
            ("android_aar", "Android AAR projection"),
            ("android_device_runtime", "canonical Android projection"),
            ("local_release_index", "local release index projection"),
        )
        for key, message in cases:
            with self.subTest(section=key):
                mismatched = copy.deepcopy(current)
                mismatched[key] = {"domain": "different"}
                with (
                    mock.patch.object(assembler, "_validate_assembled_results"),
                    self.assertRaisesRegex(
                        assembler.SourceResultsAssemblerError,
                        message,
                    ),
                ):
                    assembler._validate_verified_domain_projections(
                        previous,
                        mismatched,
                        verified=verified,
                    )

    def test_domain_closure_revalidates_projections_and_pins(self) -> None:
        previous = {"fixture": "previous"}
        current, verified = _domain_projection_fixture()
        selectors = assembler.SourceEvidenceSelectors(
            rust_handoff_manifest=RUST_HANDOFF_PATH,
            rust_handoff_sha256=RUST_HANDOFF_SHA256,
            android_runtime_run=ANDROID_RUN,
            consumer_run=CONSUMER_RUN,
        )
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        with (
            mock.patch.object(
                assembler,
                "_verify_source_domains",
                return_value=verified,
            ) as verify_domains,
            mock.patch.object(
                assembler,
                "_validate_verified_domain_projections",
            ) as validate,
            mock.patch.object(
                assembler,
                "_resample_verified_domains",
            ) as resample,
        ):
            self.assertEqual(
                verified.pins,
                assembler._verify_domain_closure(
                    previous,
                    current,
                    source=source,
                    selectors=selectors,
                ),
            )
        verify_domains.assert_called_once_with(source, selectors)
        validate.assert_called_once_with(previous, current, verified=verified)
        resample.assert_called_once_with(verified)

    def test_rust_handoff_resample_is_mandatory_and_byte_exact(self) -> None:
        _current, base = _domain_projection_fixture()
        root = pathlib.Path("/tmp/qperiapt-handoff-fixture")
        source = rust_package_handoff.RustPackageHandoffSource(
            source_commit=SOURCE_COMMIT,
            source_tree=RESULTS_COMMIT,
            canonical_source_tree_sha256=SOURCE_DIGEST,
        )
        manifest = assembler.FileSnapshot(
            path=root / "transaction.1-" / "rust-package-handoff.json",
            data=b"manifest\n",
            size=9,
            sha256="6" * 64,
        )
        transcript = assembler.FileSnapshot(
            path=manifest.path.parent / "rust-package-contract.log",
            data=b"transcript\n",
            size=11,
            sha256="7" * 64,
        )
        crate_file = assembler.FileSnapshot(
            path=manifest.path.parent / "q-periapt-core-0.1.4.crate",
            data=b"crate\n",
            size=6,
            sha256="8" * 64,
        )
        selected = rust_package_handoff.RustPackageHandoffSnapshot(
            handoff_root=root,
            inventory=frozenset(
                {manifest.path.name, transcript.path.name, crate_file.path.name}
            ),
            source=source,
            manifest=manifest,
            transcript=transcript,
            package_contract=mock.Mock(),
            crates=(
                rust_package_handoff.RustPackageHandoffCrateSnapshot(
                    name="q-periapt-core",
                    version="0.1.4",
                    dependencies=(),
                    file=crate_file,
                ),
            ),
        )
        domains = dataclasses.replace(base, rust_handoff=selected)
        with (
            mock.patch.object(assembler, "_resample_pins") as resample_pins,
            mock.patch.object(
                rust_package_handoff,
                "load_rust_package_handoff_snapshot",
                return_value=selected,
            ) as reload_handoff,
        ):
            assembler._resample_verified_domains(domains)
        resample_pins.assert_called_once_with(list(domains.pins))
        reload_handoff.assert_called_once_with(
            manifest.path,
            manifest.sha256,
            source,
            handoff_root=root,
        )

        changed = dataclasses.replace(
            selected,
            transcript=dataclasses.replace(transcript, data=b"changed\n"),
        )
        with (
            mock.patch.object(assembler, "_resample_pins"),
            mock.patch.object(
                rust_package_handoff,
                "load_rust_package_handoff_snapshot",
                return_value=changed,
            ),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "handoff changed",
            ),
        ):
            assembler._resample_verified_domains(domains)

        missing = dataclasses.replace(domains, rust_handoff=None)
        with (
            mock.patch.object(assembler, "_resample_pins"),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "handoff is missing",
            ),
        ):
            assembler._resample_verified_domains(missing)

    def test_finalize_wraps_postpublication_recheck_failure_as_committed(self) -> None:
        proof_inputs = _proof_inputs(installed=True)
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        current = {"footprint_bytes": {"fixture": True}}
        domains = mock.Mock(pins=())
        candidate = (
            assembler.SOURCE_RESULTS_ROOT
            / "transaction.fixture"
            / assembler.SOURCE_RESULTS_LEAF
        )
        injected = assembler.SourceResultsAssemblerError("injected postcommit drift")
        with (
            mock.patch.object(
                assembler,
                "capture_proof_input_digests",
                return_value=proof_inputs,
            ) as capture,
            mock.patch.object(
                assembler,
                "_assemble_source_results",
                return_value=(current, source, domains),
            ),
            mock.patch.object(
                assembler,
                "create_private_transaction_json",
                return_value=(candidate, RESULTS_DIGEST),
            ) as publish,
            mock.patch.object(assembler, "validate_baseline", return_value={}),
            mock.patch.object(
                assembler,
                "_validate_verified_domain_projections",
                side_effect=injected,
            ),
            self.assertRaises(assembler.CommittedSourceResultsError) as raised,
        ):
            assembler.finalize_source_results(
                "e" * 64,
                rust_handoff_manifest=RUST_HANDOFF_PATH,
                rust_handoff_sha256=RUST_HANDOFF_SHA256,
                android_runtime_run=ANDROID_RUN,
                consumer_run=CONSUMER_RUN,
            )

        self.assertEqual(candidate, raised.exception.path)
        self.assertEqual(RESULTS_DIGEST, raised.exception.digest)
        self.assertEqual("postcommit_recheck", raised.exception.stage)
        self.assertIs(injected, raised.exception.__cause__)
        self.assertEqual(2, capture.call_count)
        publish.assert_called_once()

    def test_cli_committed_marker_is_bounded_and_returns_125(self) -> None:
        cases = (
            (
                assembler.SOURCE_RESULTS_ROOT
                / "transaction.good"
                / assembler.SOURCE_RESULTS_LEAF,
                RESULTS_DIGEST,
                (
                    "stage=postcommit_recheck "
                    "path=target/source-results-successors/"
                    "transaction.good/results.json "
                    f"sha256={RESULTS_DIGEST}"
                ),
                None,
            ),
            (
                pathlib.Path("/private/secret/candidate.json"),
                "not-a-digest",
                "stage=postcommit_recheck path=- sha256=-",
                "/private/secret",
            ),
        )
        for path, digest, marker, forbidden in cases:
            with self.subTest(path=path):
                error = assembler.CommittedSourceResultsError(
                    path,
                    digest,
                    "postcommit_recheck",
                )
                stderr = io.StringIO()
                with (
                    mock.patch.object(assembler, "run", side_effect=error),
                    mock.patch.object(
                        sys,
                        "argv",
                        ["source_results_assembler.py", "verify-installed", "a" * 64],
                    ),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(125, assembler.main())
                output = stderr.getvalue()
                self.assertIn("SOURCE_RESULTS_POSTCOMMIT_RECHECK_ERROR", output)
                self.assertIn(marker, output)
                if forbidden is not None:
                    self.assertNotIn(forbidden, output)

    def test_cli_publication_marker_reports_only_a_safe_attempt_path(self) -> None:
        safe_path = (
            assembler.SOURCE_RESULTS_ROOT
            / "transaction.good"
            / assembler.SOURCE_RESULTS_LEAF
        )
        cases = (
            (
                safe_path,
                (
                    "path=target/source-results-successors/"
                    "transaction.good/results.json"
                ),
            ),
            (pathlib.Path("/private/secret/results.json"), "path=-"),
            (None, "path=-"),
        )
        for path, marker in cases:
            with self.subTest(path=path):
                error = assembler.PublicationReceiptCommittedError(
                    "candidate visibility changed",
                    leaf=assembler.SOURCE_RESULTS_LEAF,
                    digest=RESULTS_DIGEST,
                    visibility="committed",
                    path=path,
                )
                stderr = io.StringIO()
                with (
                    mock.patch.object(assembler, "run", side_effect=error),
                    mock.patch.object(
                        sys,
                        "argv",
                        [
                            "source_results_assembler.py",
                            "verify-installed",
                            "a" * 64,
                        ],
                    ),
                    contextlib.redirect_stderr(stderr),
                ):
                    self.assertEqual(125, assembler.main())
                output = stderr.getvalue()
                self.assertIn(marker, output)
                self.assertNotIn(str(assembler.SOURCE_RESULTS_ROOT), output)
                self.assertNotIn("/private/secret", output)

    def test_cli_structural_error_returns_two_without_traceback(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                assembler,
                "run",
                side_effect=assembler.SourceResultsAssemblerError("secret detail"),
            ),
            mock.patch.object(
                sys,
                "argv",
                ["source_results_assembler.py", "verify-installed", "a" * 64],
            ),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(2, assembler.main())
        self.assertEqual(
            "SOURCE_RESULTS_ERROR category=source_results_invalid\n",
            stderr.getvalue(),
        )

    def test_verify_installed_enforces_full_transition_call_contract(self) -> None:
        previous = _initial_baseline()
        current = _plan_current(previous)
        current["provenance"]["snapshot_commit"] = SOURCE_COMMIT
        current["proof_source_tree_sha256"] = SOURCE_DIGEST
        current["footprint_bytes"] = {"fixture": {"bytes": 1}}
        selectors = assembler.SourceEvidenceSelectors(
            rust_handoff_manifest=RUST_HANDOFF_PATH,
            rust_handoff_sha256=RUST_HANDOFF_SHA256,
            android_runtime_run=ANDROID_RUN,
            consumer_run=CONSUMER_RUN,
        )
        expected_results_sha256 = "e" * 64
        previous_bytes = assembler.canonical_json_bytes(previous)
        with (
            mock.patch.object(
                assembler,
                "validate_baseline",
                side_effect=[current, current],
            ) as validate_baseline,
            mock.patch.object(
                assembler,
                "require_direct_results_only_successor",
                return_value=RESULTS_COMMIT,
            ) as require_successor,
            mock.patch.object(
                assembler,
                "_load_git_results_bytes",
                return_value=previous_bytes,
            ) as load_parent,
            mock.patch.object(assembler, "validate_declared_currentness") as currentness,
            mock.patch.object(
                assembler,
                "validate_stable_source_currentness",
            ) as stable_currentness,
            mock.patch.object(assembler, "validate_release_publications") as publications,
            mock.patch.object(
                assembler,
                "validate_release_publication_transition",
            ) as transition,
            mock.patch.object(assembler, "_installed_worktree_identity") as identity,
            mock.patch.object(
                assembler,
                "_installed_selectors",
                return_value=selectors,
            ) as installed_selectors,
            mock.patch.object(assembler, "_verify_domain_closure") as closure,
            mock.patch.object(assembler, "verify_proof_input_digests") as verify_inputs,
            mock.patch.object(
                assembler,
                "load_footprint_manifest_section",
                return_value=(current["footprint_bytes"], "f" * 64),
            ),
        ):
            self.assertEqual(
                RESULTS_COMMIT,
                assembler.verify_installed_source_successor(
                    expected_results_sha256
                ),
            )

        self.assertEqual(
            [
                mock.call(expected_results_sha256, require_initial=False),
                mock.call(expected_results_sha256, require_initial=False),
            ],
            validate_baseline.call_args_list,
        )
        require_successor.assert_called_once_with(assembler.REPOSITORY_ROOT, SOURCE_COMMIT)
        load_parent.assert_called_once_with(
            SOURCE_COMMIT,
            label="source-parent results baseline",
        )
        currentness.assert_called_once_with(current)
        stable_currentness.assert_called_once_with(current)
        publications.assert_called_once_with(current)
        transition.assert_called_once_with(previous, current)
        self.assertEqual(
            [
                mock.call(RESULTS_COMMIT, SOURCE_DIGEST),
                mock.call(RESULTS_COMMIT, SOURCE_DIGEST),
            ],
            identity.call_args_list,
        )
        installed_selectors.assert_called_once_with(current)
        closure.assert_called_once_with(
            previous,
            current,
            source=assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST),
            selectors=selectors,
        )
        verify_inputs.assert_called_once_with(
            assembler.REPOSITORY_ROOT,
            current["proof_to_byte_inputs"],
        )

    def test_verify_installed_translates_invalid_git_transition(self) -> None:
        current = _plan_current(_initial_baseline())
        current["provenance"]["snapshot_commit"] = SOURCE_COMMIT
        current["proof_source_tree_sha256"] = SOURCE_DIGEST
        failure = GitProvenanceError("not a direct successor")
        with (
            mock.patch.object(assembler, "validate_baseline", return_value=current),
            mock.patch.object(
                assembler,
                "require_direct_results_only_successor",
                side_effect=failure,
            ),
            self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "installed results-only Git transition is invalid",
            ) as raised,
        ):
            assembler.verify_installed_source_successor("e" * 64)
        self.assertIs(failure, raised.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
