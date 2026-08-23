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

import source_results_assembler as assembler
import rust_package_handoff
from git_provenance import GitProvenanceError
from test_release_publication_contract import LEGACY_ALPHA2_SWIFT_FIELDS


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_COMMIT = "a" * 40
RESULTS_COMMIT = "b" * 40
SOURCE_DIGEST = "c" * 64
RESULTS_DIGEST = "d" * 64
ANDROID_RUN = "1" * 32
PHYSICAL_RUN = "2" * 32
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
    baseline = _live_results()
    baseline["proof_to_byte_inputs"] = _proof_inputs(installed=False)
    baseline.pop("android_physical_runtime", None)
    baseline["swift_xcframework"].pop("active_publication_key", None)
    # Restore the exact frozen legacy field bytes so the one-time neutral
    # selector migration keeps being exercised over its true input.
    baseline["swift_xcframework"].update(
        copy.deepcopy(LEGACY_ALPHA2_SWIFT_FIELDS)
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
    current["apple_device"] = _exact_section(
        assembler.APPLE_SECTION_FIELDS,
        "apple",
    )
    current["local_release_index"] = _exact_section(
        assembler.LOCAL_INDEX_SECTION_FIELDS,
        "index",
    )
    current["rust_publish"] = _exact_section(
        assembler.RUST_PACKAGE_CURRENT_SECTION_FIELDS,
        "rust",
    )
    current["android_physical_runtime"] = _exact_section(
        assembler.ANDROID_RUNTIME_SECTION_FIELDS,
        "physical",
    )
    current["android_physical_runtime"]["current_source_status"] = (
        "current_clean_tree_physical_pass"
    )
    current["performance"] = _exact_section(
        assembler.PERFORMANCE_SECTION_FIELDS,
        "performance",
    )
    current["performance"]["current_source_status"] = "current_controlled_pass"
    current["swift_xcframework"] = assembler.neutral_swift_selector(previous)
    return current


def _domain_projection_fixture() -> tuple[
    dict[str, object], assembler.VerifiedSourceDomains
]:
    current: dict[str, object] = {
        "rust_publish": {"domain": "rust"},
        "android_aar": {"domain": "aar"},
        "android_device_runtime": {"domain": "android"},
        "apple_device": {"domain": "apple"},
        "local_release_index": {"domain": "index"},
    }
    physical = mock.Mock(section={"domain": "physical"})
    performance = {"domain": "performance"}
    current["android_physical_runtime"] = copy.deepcopy(physical.section)
    current["performance"] = copy.deepcopy(performance)
    verified = assembler.VerifiedSourceDomains(
        rust_section=copy.deepcopy(current["rust_publish"]),
        rust_handoff=mock.Mock(),
        aar_section=copy.deepcopy(current["android_aar"]),
        android=mock.Mock(section=copy.deepcopy(current["android_device_runtime"])),
        apple=mock.Mock(section=copy.deepcopy(current["apple_device"])),
        index=mock.Mock(section=copy.deepcopy(current["local_release_index"])),
        physical=physical,
        performance_section=performance,
        pins=(),
    )
    return current, verified


class SourceResultsAssemblerTests(unittest.TestCase):
    def test_finalize_cli_requires_every_external_evidence_selector(self) -> None:
        command = [
            "finalize",
            "a" * 64,
            "--rust-handoff-manifest",
            RUST_HANDOFF_PATH,
            "--rust-handoff-sha256",
            RUST_HANDOFF_SHA256,
            "--android-runtime-run",
            ANDROID_RUN,
            "--apple-matrix-run",
            "matrix-1",
            "--consumer-run",
            CONSUMER_RUN,
            "--android-physical-run",
            PHYSICAL_RUN,
            "--performance-proof",
            "paired-proof.json",
        ]
        arguments = assembler._parser().parse_args(command)
        self.assertEqual(RUST_HANDOFF_PATH, arguments.rust_handoff_manifest)
        self.assertEqual(RUST_HANDOFF_SHA256, arguments.rust_handoff_sha256)
        self.assertEqual(PHYSICAL_RUN, arguments.android_physical_run)
        self.assertEqual("paired-proof.json", arguments.performance_proof)
        required_flags = (
            "--rust-handoff-manifest",
            "--rust-handoff-sha256",
            "--android-runtime-run",
            "--apple-matrix-run",
            "--consumer-run",
            "--android-physical-run",
            "--performance-proof",
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

    def test_internal_apis_require_physical_and_performance_selectors(self) -> None:
        selector_fields = assembler.SourceEvidenceSelectors.__dataclass_fields__
        for name in ("android_physical_run", "performance_proof"):
            with self.subTest(dataclass_field=name):
                self.assertIs(dataclasses.MISSING, selector_fields[name].default)

        for function in (
            assembler._assemble_source_results,
            assembler.assemble_source_results,
            assembler.finalize_source_results,
        ):
            parameters = inspect.signature(function).parameters
            for name in ("android_physical_run", "performance_proof"):
                with self.subTest(function=function.__name__, parameter=name):
                    self.assertIs(inspect.Parameter.empty, parameters[name].default)

    def test_short_selectors_accept_only_canonical_bounded_leaves(self) -> None:
        for value in ("run-1", "A_1.2", "z" * 128):
            with self.subTest(valid=value):
                self.assertEqual(value, assembler._short_selector(value, "selector"))

        invalid: tuple[object, ...] = (
            "",
            ".",
            "..",
            "-leading",
            "contains/slash",
            "contains\\backslash",
            "contains space",
            "全角",
            "z" * 129,
            7,
        )
        for value in invalid:
            with self.subTest(invalid=value), self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "safe short selector",
            ):
                assembler._short_selector(cast(str, value), "selector")

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

    def test_physical_android_projection_requires_arm64_release_mode(self) -> None:
        proof = {
            "android": {"build_tools": "36.0.0"},
            "device": {
                "abi": "arm64-v8a",
                "kind": "physical",
                "page_size": 4_096,
                "sdk": 36,
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
                PHYSICAL_RUN,
                assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST),
                physical=True,
            )

        self.assertEqual("arm64-v8a", projection.section["device_abi"])
        self.assertIs(True, projection.section["release_candidate_mode"])
        verify_contents.assert_called_once_with(
            assembler.REPOSITORY_ROOT,
            proof,
            proof_paths,
            expected_device_kind="physical",
            expected_device_abi="arm64-v8a",
            expected_page_size=None,
            expected_device_sdk=None,
            require_release_mode=True,
            allow_dirty_proof=False,
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
            assembler._validate_baseline_document_shape(
                baseline,
                require_initial=False,
            )
            assembler.validate_declared_currentness(baseline)
            with self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                "one-time proof-input migration",
            ):
                assembler._validate_baseline_document_shape(
                    baseline,
                    require_initial=True,
                )
            return

        # Frozen initial baseline state (source_ci_gate's initial dispatch).
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
            "apple_device": {
                "matrix_proof_path": (
                    "artifact/device-runs/matrix-1/"
                    "apple-device-matrix-proof.json"
                )
            },
            "local_release_index": {
                "consumer_receipt_run_id": CONSUMER_RUN,
                "consumer_receipt_path": assembler._relative(
                    assembler.CONSUMER_RECEIPTS_ROOT
                    / CONSUMER_RUN
                    / assembler.release_consumer_smoke.CONSUMER_RECEIPT_LEAF
                ),
            },
            "android_physical_runtime": {
                "current_source_status": "current_clean_tree_physical_pass",
                "run_id": PHYSICAL_RUN,
                "proof_path": assembler._relative(
                    assembler._android_proof_path(PHYSICAL_RUN)
                ),
            },
            "performance": {
                "current_source_status": "current_controlled_pass",
                "proof_path": "target/performance/paired-proof.json",
            },
        }
        self.assertEqual(
            assembler.SourceEvidenceSelectors(
                rust_handoff_manifest=RUST_HANDOFF_PATH,
                rust_handoff_sha256=RUST_HANDOFF_SHA256,
                android_runtime_run=ANDROID_RUN,
                apple_matrix_run="matrix-1",
                consumer_run=CONSUMER_RUN,
                android_physical_run=PHYSICAL_RUN,
                performance_proof="paired-proof.json",
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

        for section, message in (
            (
                "android_physical_runtime",
                "require current physical Android evidence",
            ),
            ("performance", "require current performance evidence"),
        ):
            stale = copy.deepcopy(current)
            stale[section]["current_source_status"] = "stale_requires_rerun"
            with self.subTest(stale_section=section), self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                message,
            ):
                assembler._installed_selectors(stale)

    def test_assemble_document_requires_current_physical_and_performance(self) -> None:
        previous = _initial_baseline()
        original = copy.deepcopy(previous)
        source = assembler.SourceIdentity(SOURCE_COMMIT, SOURCE_DIGEST)
        proof_inputs = _proof_inputs(installed=True)
        footprint = {"fixture": {"bytes": 1}}
        rust = _exact_section(assembler.RUST_PACKAGE_CURRENT_SECTION_FIELDS, "rust")
        aar = _exact_section(assembler.ANDROID_AAR_SECTION_FIELDS, "aar")
        android = _exact_section(assembler.ANDROID_RUNTIME_SECTION_FIELDS, "android")
        physical = _exact_section(
            assembler.ANDROID_RUNTIME_SECTION_FIELDS,
            "physical",
        )
        physical["current_source_status"] = "current_clean_tree_physical_pass"
        performance = _exact_section(
            assembler.PERFORMANCE_SECTION_FIELDS,
            "performance",
        )
        performance["current_source_status"] = "current_controlled_pass"
        apple = _exact_section(assembler.APPLE_SECTION_FIELDS, "apple")
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
                apple_section=apple,
                index_section=index,
                physical_section=physical,
                performance_section=performance,
            )

        stable_currentness.assert_called_once_with(current)

        self.assertEqual(original, previous)
        self.assertEqual(SOURCE_COMMIT, current["provenance"]["snapshot_commit"])
        self.assertEqual(SOURCE_DIGEST, current["proof_source_tree_sha256"])
        self.assertEqual(physical, current["android_physical_runtime"])
        self.assertEqual(performance, current["performance"])

        aar["aar_sha256"] = "mutated after assembly"
        physical["proof_sha256"] = "mutated after assembly"
        performance["proof_sha256"] = "mutated after assembly"
        self.assertNotEqual("mutated after assembly", current["android_aar"]["aar_sha256"])
        self.assertNotEqual(
            "mutated after assembly",
            current["android_physical_runtime"]["proof_sha256"],
        )
        self.assertNotEqual(
            "mutated after assembly",
            current["performance"]["proof_sha256"],
        )

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

    def test_mutation_plan_rejects_stale_required_domains(self) -> None:
        previous = _initial_baseline()
        current = _plan_current(previous)
        assembler.plan_authorized_mutations(previous, current)

        for section, message in (
            (
                "android_physical_runtime",
                "require current physical Android evidence",
            ),
            ("performance", "require current performance evidence"),
        ):
            stale = copy.deepcopy(current)
            stale[section]["current_source_status"] = "stale_requires_rerun"
            with self.subTest(stale_section=section), self.assertRaisesRegex(
                assembler.SourceResultsAssemblerError,
                message,
            ):
                assembler.plan_authorized_mutations(previous, stale)

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
            physical=verified.physical,
        )

    def test_verified_domain_projection_mismatches_fail_closed(self) -> None:
        previous = {"fixture": "previous"}
        current, verified = _domain_projection_fixture()
        cases = (
            ("rust_publish", "Rust package projection"),
            ("android_aar", "Android AAR projection"),
            ("android_device_runtime", "canonical Android projection"),
            ("apple_device", "Apple matrix projection"),
            ("local_release_index", "local release index projection"),
            ("android_physical_runtime", "physical Android projection"),
            ("performance", "performance projection"),
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
            apple_matrix_run="matrix-1",
            consumer_run=CONSUMER_RUN,
            android_physical_run=PHYSICAL_RUN,
            performance_proof="paired-proof.json",
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
            path=manifest.path.parent / "q-periapt-core-0.1.3.crate",
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
                    version="0.1.3",
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
                apple_matrix_run="matrix-1",
                consumer_run=CONSUMER_RUN,
                android_physical_run=PHYSICAL_RUN,
                performance_proof="paired-proof.json",
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
            apple_matrix_run="matrix-1",
            consumer_run=CONSUMER_RUN,
            android_physical_run=PHYSICAL_RUN,
            performance_proof="paired-proof.json",
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
