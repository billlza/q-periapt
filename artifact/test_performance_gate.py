from __future__ import annotations

import hashlib
import io
import json
import pathlib
import tempfile
import types
import unittest
from typing import Protocol
from unittest import mock

import performance_gate


class CommandOutput(Protocol):
    def __call__(
        self,
        args: list[str],
        cwd: pathlib.Path,
        *,
        environment: dict[str, str] | None = None,
    ) -> str: ...


class PerformanceGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.raw = self.root / "raw.jsonl"
        self.budget = {
            "schema_version": 8,
            "harness_schema_version": 3,
            "mode": "release_evidence",
            "target": "aarch64-apple-darwin",
            "schedule": "ABBA/BAAB",
            "corpus_size": 2,
            "iterations_per_sample": {
                "combine": 256,
                "encapsulate": 1,
                "decapsulate": 2,
            },
            "min_samples_per_variant_operation": 8,
            "collection_samples_per_variant_operation": 8,
            "warmup_ms": 1,
            "pair_block_size": 4,
            "regression_guard_pair_block_size": 2,
            "min_p99_tail_observations_per_pair_block": 1,
            "stability_block_sizes": {
                "combine": 2,
                "encapsulate": 2,
                "decapsulate": 2,
            },
            "bootstrap_estimate_block_span": 1,
            "max_block_median_cv": 0.05,
            "toolchain": {
                "ar_path": str(performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar"),
                "ar_sha256": "4" * 64,
                "cargo_sha256": "1" * 64,
                "cargo_version": "cargo test",
                "clang_path": str(
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang"
                ),
                "clang_sha256": "3" * 64,
                "clang_version": "Apple clang version test",
                "rustc_sha256": "2" * 64,
                "rustc_version": "rustc test",
                "rustup_toolchain": "test-pinned",
                "sdk_path": str(
                    performance_gate.macos_sdk_path_for_toolchain(
                        performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN
                    )
                ),
                "sdk_settings_sha256": "5" * 64,
                "sdk_version": "test-sdk",
                "target": "aarch64-apple-darwin",
            },
            "profile_non_regression": {
                "backend": "matched-test-backend",
                "direction": "ContextBound/CompatXWing",
                "operations": {
                    "combine": {
                        "max_block_median_p95_delta_ns_upper_95": 10000
                    },
                    "encapsulate": {
                        "max_block_median_p50_ratio_upper_95": 1.10,
                        "max_block_median_p95_ratio_upper_95": 1.15,
                        "max_block_median_p99_ratio_upper_95": 1.20,
                        "max_block_median_p95_delta_ns_upper_95": 15000,
                    },
                    "decapsulate": {
                        "max_block_median_p50_ratio_upper_95": 1.10,
                        "max_block_median_p95_ratio_upper_95": 1.15,
                        "max_block_median_p99_ratio_upper_95": 1.20,
                        "max_block_median_p95_delta_ns_upper_95": 15000,
                    },
                },
            },
            "implementation_improvement": {
                "direction": "native/portable",
                "native_implementation_id": performance_gate.NATIVE_IMPLEMENTATION_ID,
                "portable_implementation_id": (
                    performance_gate.PORTABLE_REFERENCE_IMPLEMENTATION_ID
                ),
                "product_profile": "ContextBound",
                "reference_scope": performance_gate.PORTABLE_REFERENCE_SCOPE,
                "operations": {
                    "encapsulate": dict(
                        performance_gate.IMPLEMENTATION_IMPROVEMENT_LIMITS
                    ),
                    "decapsulate": dict(
                        performance_gate.IMPLEMENTATION_IMPROVEMENT_LIMITS
                    ),
                },
            },
        }
        self.write_raw()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_raw(
        self,
        *,
        slow_bound: bool = False,
        unstable: bool = False,
        quantized_combine: bool = False,
        common_drift: bool = False,
        slow_drift: bool = False,
        primary_pass_guard_fail: bool = False,
        slow_native: bool = False,
    ) -> None:
        metadata = {
            "schema_version": 3,
            "record_type": "metadata",
            "mode": "release_evidence",
            "target": "aarch64-apple-darwin",
            "schedule": "ABBA/BAAB",
            "corpus_size": 2,
            "samples_per_variant_operation": 8,
            "iterations_per_sample": {
                "combine": 256,
                "encapsulate": 1,
                "decapsulate": 2,
            },
            "warmup_ms": 1,
            "suite_id_hex": "00",
            "policy_version": 1,
            "application_context_hex": "01",
            "profile_non_regression": {
                "backend": "matched-test-backend",
                "direction": "ContextBound/CompatXWing",
                "operations": ["combine", "encapsulate", "decapsulate"],
                "variants": ["ContextBound", "CompatXWing"],
            },
            "implementation_improvement": {
                "digest_algorithm": "SHA3-256",
                "direction": "native/portable",
                "equivalence_cases_per_operation": {
                    "keypair": 1,
                    "encapsulate": 2,
                    "decapsulate": 2,
                },
                "native_implementation_id": performance_gate.NATIVE_IMPLEMENTATION_ID,
                "operations": ["encapsulate", "decapsulate"],
                "portable_implementation_id": (
                    performance_gate.PORTABLE_REFERENCE_IMPLEMENTATION_ID
                ),
                "product_profile": "ContextBound",
                "reference_scope": performance_gate.PORTABLE_REFERENCE_SCOPE,
                "variants": ["native", "portable"],
            },
        }
        records = [metadata]
        for operation, case_count in (("keypair", 1), ("encapsulate", 2), ("decapsulate", 2)):
            for case_id in range(case_count):
                records.append(
                    {
                        "schema_version": 3,
                        "record_type": "equivalence",
                        "operation": operation,
                        "case_id": case_id,
                        "corpus_index": 0 if operation == "keypair" else case_id,
                        "input_digest_hex": f"{case_id + 1:064x}",
                        "native_output_digest_hex": "b" * 64,
                        "portable_output_digest_hex": "b" * 64,
                    }
                )
        estimands = (
            (
                performance_gate.PROFILE_NON_REGRESSION,
                performance_gate.OPERATIONS,
                performance_gate.PROFILES,
            ),
            (
                performance_gate.IMPLEMENTATION_IMPROVEMENT,
                performance_gate.IMPLEMENTATION_OPERATIONS,
                performance_gate.IMPLEMENTATIONS,
            ),
        )
        for estimand, operations, variants in estimands:
            for operation in operations:
                schedule: list[tuple[str, int]] = []
                for cycle in range(metadata["samples_per_variant_operation"] // 2):
                    first_pair = cycle * 2
                    left, right = variants
                    schedule.extend(
                        [
                            (left, first_pair),
                            (right, first_pair),
                            (right, first_pair + 1),
                            (left, first_pair + 1),
                        ]
                        if cycle % 2 == 0
                        else [
                            (right, first_pair),
                            (left, first_pair),
                            (left, first_pair + 1),
                            (right, first_pair + 1),
                        ]
                    )
                for schedule_index, (variant, pair_id) in enumerate(schedule):
                    if estimand == performance_gate.PROFILE_NON_REGRESSION:
                        compat = 500 if operation == "combine" else 100_000
                        bound = 5_500 if operation == "combine" else 105_000
                        elapsed = bound if variant == "ContextBound" else compat
                        if slow_bound and operation == "encapsulate" and variant == "ContextBound":
                            elapsed = 140_000
                        if primary_pass_guard_fail and operation == "encapsulate":
                            slow_guard_half = pair_id % 4 < 2
                            elapsed = (
                                140_000
                                if (variant == "ContextBound") == slow_guard_half
                                else 100_000
                            )
                    else:
                        elapsed = 80_000 if variant == "native" else 100_000
                        if slow_native and operation == "encapsulate" and variant == "native":
                            elapsed = 101_000
                    iterations = metadata["iterations_per_sample"][operation]
                    elapsed_ns_total = elapsed * iterations
                    if (
                        quantized_combine
                        and estimand == performance_gate.PROFILE_NON_REGRESSION
                        and operation == "combine"
                        and variant == "CompatXWing"
                    ):
                        elapsed_ns_total = 334 * iterations + (41 if pair_id >= 2 else 0)
                    if common_drift:
                        elapsed_ns_total = elapsed_ns_total * (100 + pair_id) // 100
                    if slow_drift:
                        elapsed_ns_total = elapsed_ns_total * (100 + 20 * pair_id) // 100
                    if unstable and pair_id >= 2:
                        elapsed_ns_total *= 2
                    records.append(
                        {
                            "schema_version": 3,
                            "record_type": "sample",
                            "estimand": estimand,
                            "operation": operation,
                            "variant": variant,
                            "pair_id": pair_id,
                            "schedule_index": schedule_index,
                            "corpus_index": pair_id % 2,
                            "elapsed_ns_total": elapsed_ns_total,
                        }
                    )
        self.raw.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    def record_line_index(
        self,
        lines: list[str],
        *,
        record_type: str,
        estimand: str | None = None,
        operation: str | None = None,
        variant: str | None = None,
        ordinal: int = 0,
    ) -> int:
        matches: list[int] = []
        for index, line in enumerate(lines):
            record = json.loads(line)
            if record.get("record_type") != record_type:
                continue
            if estimand is not None and record.get("estimand") != estimand:
                continue
            if operation is not None and record.get("operation") != operation:
                continue
            if variant is not None and record.get("variant") != variant:
                continue
            matches.append(index)
        self.assertGreater(len(matches), ordinal)
        return matches[ordinal]

    def parse_and_analyse(self) -> dict[str, object]:
        metadata, grouped = performance_gate.parse_raw(self.raw)
        return performance_gate.analyse(metadata, grouped, self.budget)

    def controlled_environment(self) -> dict[str, object]:
        return {
            "system": "Darwin",
            "release": "test-release",
            "machine": "arm64",
            "cpu": "test-cpu",
            "thermal": "nominal",
            "ac_power": True,
            "controlled": True,
        }

    def proof_toolchain_identity(self) -> dict[str, str]:
        return {
            "ar_path": str(performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar"),
            "ar_sha256": "4" * 64,
            "cargo": "cargo test",
            "cargo_path": "/synthetic/toolchain/cargo",
            "cargo_sha256": "1" * 64,
            "clang": "Apple clang version test",
            "clang_path": str(
                performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang"
            ),
            "clang_sha256": "3" * 64,
            "rustc": "rustc test",
            "rustc_path": "/synthetic/toolchain/rustc",
            "rustc_sha256": "2" * 64,
            "sdk_path": str(
                performance_gate.macos_sdk_path_for_toolchain(
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN
                )
            ),
            "sdk_settings_sha256": "5" * 64,
            "sdk_version": "test-sdk",
            "target": "aarch64-apple-darwin",
        }

    def synthetic_toolchain(
        self, account_home: pathlib.Path, name: str = "pinned"
    ) -> tuple[
        pathlib.Path,
        pathlib.Path,
        pathlib.Path,
        pathlib.Path,
        dict[str, str],
        CommandOutput,
    ]:
        tool_bin = account_home / ".rustup" / "toolchains" / name / "bin"
        tool_bin.mkdir(parents=True)
        cargo = tool_bin / "cargo"
        rustc = tool_bin / "rustc"
        for path, content in ((cargo, b"cargo"), (rustc, b"rustc")):
            path.write_bytes(content)
            path.chmod(0o700)
        cargo = cargo.resolve()
        rustc = rustc.resolve()
        xcode_bin = (
            self.root
            / "Applications"
            / "Xcode.app"
            / "Contents"
            / "Developer"
            / "Toolchains"
            / "XcodeDefault.xctoolchain"
            / "usr"
            / "bin"
        )
        xcode_bin.mkdir(parents=True, exist_ok=True)
        clang = xcode_bin / "clang"
        ar = xcode_bin / "ar"
        for path, content in ((clang, b"clang"), (ar, b"ar")):
            path.write_bytes(content)
            path.chmod(0o700)
        clang = clang.resolve()
        ar = ar.resolve()
        xcode_bin = clang.parent
        sdk = performance_gate.macos_sdk_path_for_toolchain(xcode_bin)
        sdk.mkdir(parents=True)
        sdk_settings = b'{"Version":"test-sdk"}'
        (sdk / performance_gate.MACOS_SDK_SETTINGS_NAME).write_bytes(sdk_settings)
        policy = {
            "ar_path": str(ar),
            "ar_sha256": hashlib.sha256(b"ar").hexdigest(),
            "cargo_sha256": hashlib.sha256(b"cargo").hexdigest(),
            "cargo_version": "cargo pinned",
            "clang_path": str(clang),
            "clang_sha256": hashlib.sha256(b"clang").hexdigest(),
            "clang_version": "Apple clang version pinned",
            "rustc_sha256": hashlib.sha256(b"rustc").hexdigest(),
            "rustc_version": "rustc pinned",
            "rustup_toolchain": name,
            "sdk_path": str(sdk),
            "sdk_settings_sha256": hashlib.sha256(sdk_settings).hexdigest(),
            "sdk_version": "test-sdk",
            "target": "aarch64-test-target",
        }

        def command_output(
            args: list[str], _cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            del environment
            if args == [str(cargo), "--version"]:
                return "cargo pinned"
            if args == [str(rustc), "--version"]:
                return "rustc pinned"
            if args == [str(clang), "--version"]:
                return "Apple clang version pinned\nTarget: aarch64-test-target"
            if args == [str(rustc), "-vV"]:
                return "host: aarch64-test-target"
            self.fail(f"unexpected command: {args}")

        return cargo, rustc, clang, ar, policy, command_output

    def make_synthetic_proof(self, *, manifest_bound: bool) -> dict[str, object]:
        target = self.root / "target" / "performance"
        target.mkdir(parents=True, exist_ok=True)
        raw_path = target / "synthetic.jsonl"
        raw_path.write_bytes(self.raw.read_bytes())

        artifact = self.root / "artifact"
        artifact.mkdir(exist_ok=True)
        budget_path = artifact / "performance-budgets.json"
        budget_path.write_text(
            json.dumps(self.budget, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        binary_bytes = b"synthetic performance evidence binary"
        binary_digest = hashlib.sha256(binary_bytes).hexdigest()
        binary_path = (
            target
            / "binaries"
            / "aarch64-apple-darwin"
            / f"paired_profile_perf-{binary_digest}"
        )
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        binary_path.write_bytes(binary_bytes)
        binary_path.chmod(0o700)
        portable_archive_bytes = b"synthetic portable reference archive"
        portable_archive_digest = hashlib.sha256(
            portable_archive_bytes
        ).hexdigest()
        portable_archive_path = (
            binary_path.parent
            / f"portable-reference-{portable_archive_digest}.a"
        )
        portable_archive_path.write_bytes(portable_archive_bytes)
        portable_archive_path.chmod(0o600)
        portable_source_path = self.root.joinpath(
            *performance_gate.PORTABLE_REFERENCE_SOURCE_RELATIVE.parts
        )
        portable_source_path.parent.mkdir(parents=True, exist_ok=True)
        portable_source_path.write_bytes(b"synthetic portable reference source")
        portable_source_digest = hashlib.sha256(
            portable_source_path.read_bytes()
        ).hexdigest()

        metadata, grouped = performance_gate.parse_raw(raw_path)
        analysis = performance_gate.analyse(metadata, grouped, self.budget)
        environment = {
            label: self.controlled_environment()
            for label in ("pre_build", "pre_run", "post_run", "post_analysis")
        }
        tree_digest = "a" * 64
        toolchain = self.proof_toolchain_identity()
        proof_path = target / "synthetic-proof.json"
        with (
            mock.patch.object(performance_gate, "git_commit", return_value="b" * 40),
            mock.patch.object(performance_gate, "source_tree_dirty", return_value=True),
        ):
            performance_gate.emit_proof(
                self.root,
                raw_path,
                proof_path,
                metadata,
                analysis,
                environment,
                tree_digest,
                binary_path,
                binary_digest,
                portable_archive_path,
                portable_archive_digest,
                portable_source_digest,
                toolchain,
                hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                hashlib.sha256(budget_path.read_bytes()).hexdigest(),
            )

        args = types.SimpleNamespace(
            root=self.root.resolve(),
            proof=proof_path.resolve(),
            max_age_seconds=performance_gate.DEFAULT_MAX_AGE_SECONDS,
            allow_dirty=True,
            allow_uncontrolled=False,
            results_manifest=None,
            expected_results_manifest_sha256=None,
        )
        if manifest_bound:
            proof_digest = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            manifest_path = artifact / "results.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "proof_source_tree_sha256": tree_digest,
                        "performance": {
                            "current_source_status": "current_controlled_pass",
                            "proof_schema": performance_gate.PROOF_SCHEMA_VERSION,
                            "proof_source_tree_sha256": tree_digest,
                            "proof_path": proof_path.relative_to(self.root).as_posix(),
                            "proof_sha256": proof_digest,
                            "proof_generated_at": "2026-07-11T00:00:00Z",
                            "status": "pass",
                        },
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            args.results_manifest = manifest_path.resolve()
            args.expected_results_manifest_sha256 = hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest()

        return {
            "args": args,
            "raw": raw_path,
            "budget": budget_path,
            "binary": binary_path,
            "portable_archive": portable_archive_path,
            "portable_source": portable_source_path,
            "proof": proof_path,
            "tree_digest": tree_digest,
            "toolchain": toolchain,
            "environment": self.controlled_environment(),
        }

    def verify_synthetic_proof(
        self,
        fixture: dict[str, object],
        *,
        tree_digest: str | None = None,
        toolchain: dict[str, str] | None = None,
    ) -> None:
        selected_toolchain = toolchain or fixture["toolchain"]
        with (
            mock.patch.object(
                performance_gate,
                "require_commit_or_evidence_successor",
            ),
            mock.patch.object(
                performance_gate,
                "source_tree_digest",
                return_value=tree_digest or fixture["tree_digest"],
            ),
            mock.patch.object(
                performance_gate,
                "verified_toolchain",
                return_value=(
                    selected_toolchain,
                    pathlib.Path("/synthetic/toolchain/cargo"),
                    pathlib.Path("/synthetic/toolchain/rustc"),
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang",
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar",
                ),
            ),
            mock.patch.object(performance_gate, "require_toolchain_unchanged"),
            mock.patch.object(
                performance_gate,
                "collect_environment",
                return_value=fixture["environment"],
            ),
        ):
            performance_gate.verify(fixture["args"])

    def test_matching_paired_data_passes(self) -> None:
        result = self.parse_and_analyse()
        self.assertLessEqual(
            result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"]["paired"][
                "block_median_p50_ratio_upper_95"
            ],
            1.10,
        )
        self.assertEqual(
            result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "pair_block_size"
            ],
            4,
        )
        self.assertEqual(
            result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "regression_guard_pair_block_size"
            ],
            2,
        )
        self.assertLessEqual(
            result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "regression_guard_paired"
            ][
                "block_median_p50_ratio_upper_95"
            ],
            1.10,
        )
        for operation in performance_gate.IMPLEMENTATION_OPERATIONS:
            with self.subTest(operation=operation):
                implementation = result[performance_gate.IMPLEMENTATION_IMPROVEMENT][
                    operation
                ]
                self.assertEqual(implementation["direction"], "native/portable")
                self.assertLessEqual(
                    implementation["paired"][
                        "block_median_p50_ratio_upper_95"
                    ],
                    0.95,
                )

    def test_emit_and_manifest_bound_full_verify_pass(self) -> None:
        fixture = self.make_synthetic_proof(manifest_bound=True)
        self.verify_synthetic_proof(fixture)

    def test_collect_orchestrates_fresh_build_run_emit_and_full_verify(self) -> None:
        artifact = self.root / "artifact"
        artifact.mkdir()
        budget_path = artifact / "performance-budgets.json"
        budget_path.write_text(
            json.dumps(self.budget, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        target = self.root / "target" / "performance"
        raw_path = target / "collected.jsonl"
        proof_path = target / "collected-proof.json"
        tree_digest = "a" * 64
        controlled = self.controlled_environment()
        toolchain = self.proof_toolchain_identity()
        binary_bytes = b"fresh synthetic collector binary"
        portable_archive_bytes = b"fresh synthetic portable archive"

        def fake_portable_build(
            root: pathlib.Path,
            _target: str,
            _clang: pathlib.Path,
            _ar: pathlib.Path,
            output_dir: pathlib.Path,
            _environment: dict[str, str],
        ) -> tuple[pathlib.Path, str, str]:
            archive = (
                output_dir
                / f"lib{performance_gate.PORTABLE_REFERENCE_ARCHIVE_STEM}.a"
            )
            archive.write_bytes(portable_archive_bytes)
            source = root.joinpath(
                *performance_gate.PORTABLE_REFERENCE_SOURCE_RELATIVE.parts
            )
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"fresh synthetic portable source")
            return (
                archive.resolve(),
                hashlib.sha256(portable_archive_bytes).hexdigest(),
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

        def fake_build(
            _root: pathlib.Path,
            selected_target: str,
            _cargo: pathlib.Path,
            target_dir: pathlib.Path,
            _environment: dict[str, str],
        ) -> tuple[pathlib.Path, str]:
            executable = performance_gate.binary_path(target_dir, selected_target)
            executable.parent.mkdir(parents=True)
            executable.write_bytes(binary_bytes)
            executable.chmod(0o700)
            return executable.resolve(), hashlib.sha256(binary_bytes).hexdigest()

        def fake_run(command: list[str], **kwargs: object) -> object:
            self.assertEqual(pathlib.Path(command[0]).name, "paired_profile_perf")
            self.assertEqual(
                command[1:],
                [
                    "--samples",
                    str(self.budget["collection_samples_per_variant_operation"]),
                    "--warmup-ms",
                    str(self.budget["warmup_ms"]),
                    "--raw-out",
                    str(raw_path.resolve()),
                ],
            )
            self.assertEqual(self.root.resolve(), kwargs.get("cwd"))
            self.assertIs(kwargs.get("check"), True)
            self.assertIsInstance(kwargs.get("env"), dict)
            self.assertNotIn("shell", kwargs)
            output = pathlib.Path(command[command.index("--raw-out") + 1])
            output.write_bytes(self.raw.read_bytes())
            return types.SimpleNamespace(returncode=0)

        collect_args = types.SimpleNamespace(
            root=self.root.resolve(),
            raw=raw_path.resolve(),
            proof=proof_path.resolve(),
            allow_dirty=True,
            allow_uncontrolled=False,
        )
        with (
            mock.patch.object(
                performance_gate, "collect_environment", return_value=controlled
            ),
            mock.patch.object(
                performance_gate, "source_tree_digest", return_value=tree_digest
            ),
            mock.patch.object(
                performance_gate,
                "verified_toolchain",
                return_value=(
                    toolchain,
                    pathlib.Path("/synthetic/toolchain/cargo"),
                    pathlib.Path("/synthetic/toolchain/rustc"),
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang",
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar",
                ),
            ),
            mock.patch.object(
                performance_gate, "hardened_cargo_environment", return_value={}
            ),
            mock.patch.object(
                performance_gate,
                "build_portable_reference_archive",
                side_effect=fake_portable_build,
            ),
            mock.patch.object(performance_gate, "build_harness", side_effect=fake_build),
            mock.patch.object(performance_gate.subprocess, "run", side_effect=fake_run),
            mock.patch.object(
                performance_gate, "require_toolchain_unchanged"
            ) as unchanged,
            mock.patch.object(performance_gate, "git_commit", return_value="b" * 40),
            mock.patch.object(performance_gate, "source_tree_dirty", return_value=True),
        ):
            performance_gate.collect(collect_args)

        self.assertEqual(unchanged.call_count, 3)
        for call in unchanged.call_args_list:
            self.assertEqual(len(call.args), 6)
            self.assertEqual(call.args[1], toolchain)
            self.assertEqual(
                call.args[2:],
                (
                    pathlib.Path("/synthetic/toolchain/cargo"),
                    pathlib.Path("/synthetic/toolchain/rustc"),
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang",
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar",
                ),
            )
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        fixture = {
            "args": types.SimpleNamespace(
                root=self.root.resolve(),
                proof=proof_path.resolve(),
                max_age_seconds=performance_gate.DEFAULT_MAX_AGE_SECONDS,
                allow_dirty=True,
                allow_uncontrolled=False,
                results_manifest=None,
                expected_results_manifest_sha256=None,
            ),
            "raw": raw_path,
            "budget": budget_path,
            "binary": self.root / proof["artifacts"]["binary_path"],
            "portable_archive": (
                self.root / proof["artifacts"]["portable_reference_archive_path"]
            ),
            "portable_source": self.root.joinpath(
                *performance_gate.PORTABLE_REFERENCE_SOURCE_RELATIVE.parts
            ),
            "proof": proof_path,
            "tree_digest": tree_digest,
            "toolchain": toolchain,
            "environment": controlled,
        }
        self.assertEqual(raw_path.read_bytes(), self.raw.read_bytes())
        self.verify_synthetic_proof(fixture)

    def test_final_collection_resample_rejects_every_late_drift(self) -> None:
        file_cases = (
            ("proof", "performance proof changed during proof emission"),
            ("raw", "raw performance data changed during proof emission"),
            ("binary", "performance binary changed during proof emission"),
            (
                "portable_archive",
                "portable reference archive changed during proof emission",
            ),
            (
                "portable_source",
                "portable reference source changed during proof emission",
            ),
            ("budget", "performance budget changed during proof emission"),
        )
        state_cases = (
            ("source", "source tree changed during performance proof emission"),
            ("dirty", "source tree became dirty during performance proof emission"),
            ("toolchain", "macOS SDK settings changed during performance evidence processing"),
        )
        for case, message in (*file_cases, *state_cases):
            with self.subTest(case=case):
                fixture = self.make_synthetic_proof(manifest_bound=False)
                raw_snapshot = performance_gate.read_regular_snapshot(
                    fixture["raw"],
                    maximum=performance_gate.MAX_PERFORMANCE_RAW_BYTES,
                    label="test raw performance data",
                )
                budget_snapshot = performance_gate.load_json_object_snapshot(
                    fixture["budget"],
                    maximum=performance_gate.MAX_PERFORMANCE_BUDGET_BYTES,
                    label="test performance budget",
                )
                proof_payload = json.loads(
                    fixture["proof"].read_text(encoding="utf-8")
                )
                binary_digest = hashlib.sha256(
                    fixture["binary"].read_bytes()
                ).hexdigest()
                portable_archive_digest = hashlib.sha256(
                    fixture["portable_archive"].read_bytes()
                ).hexdigest()
                portable_source_digest = hashlib.sha256(
                    fixture["portable_source"].read_bytes()
                ).hexdigest()
                if case in {name for name, _message in file_cases}:
                    path = fixture[case]
                    path.write_bytes(path.read_bytes() + b" ")

                source_digest = (
                    "c" * 64 if case == "source" else fixture["tree_digest"]
                )
                allow_dirty = case != "dirty"
                toolchain_error = (
                    performance_gate.GateError(
                        "macOS SDK settings changed during performance evidence processing"
                    )
                    if case == "toolchain"
                    else None
                )
                with (
                    mock.patch.object(
                        performance_gate,
                        "source_tree_digest",
                        return_value=source_digest,
                    ),
                    mock.patch.object(
                        performance_gate,
                        "source_tree_dirty",
                        return_value=case == "dirty",
                    ),
                    mock.patch.object(
                        performance_gate,
                        "require_toolchain_unchanged",
                        side_effect=toolchain_error,
                    ),
                    self.assertRaisesRegex(performance_gate.GateError, message),
                ):
                    performance_gate.verify_emitted_collection(
                        self.root,
                        allow_dirty=allow_dirty,
                        tree_digest=fixture["tree_digest"],
                        raw_path=fixture["raw"],
                        raw_snapshot=raw_snapshot,
                        proof_path=fixture["proof"],
                        proof_payload=proof_payload,
                        evidence_binary=fixture["binary"],
                        binary_digest=binary_digest,
                        evidence_portable_archive=fixture["portable_archive"],
                        portable_archive_digest=portable_archive_digest,
                        portable_source_digest=portable_source_digest,
                        budget_path=fixture["budget"],
                        budget_snapshot=budget_snapshot,
                        toolchain=fixture["toolchain"],
                        cargo=pathlib.Path("/synthetic/toolchain/cargo"),
                        rustc=pathlib.Path("/synthetic/toolchain/rustc"),
                        clang=performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang",
                        ar=performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar",
                    )

    def test_final_collection_compares_proof_content_not_only_reported_hash(self) -> None:
        fixture = self.make_synthetic_proof(manifest_bound=False)
        raw_snapshot = performance_gate.read_regular_snapshot(
            fixture["raw"],
            maximum=performance_gate.MAX_PERFORMANCE_RAW_BYTES,
            label="test raw performance data",
        )
        budget_snapshot = performance_gate.load_json_object_snapshot(
            fixture["budget"],
            maximum=performance_gate.MAX_PERFORMANCE_BUDGET_BYTES,
            label="test performance budget",
        )
        proof_payload = json.loads(fixture["proof"].read_text(encoding="utf-8"))
        expected_proof = performance_gate.canonical_proof_bytes(proof_payload)
        forged_payload = dict(proof_payload)
        forged_payload["gate"] = {"passed": False}
        forged_bytes = performance_gate.canonical_proof_bytes(forged_payload)
        forged_snapshot = performance_gate.JsonObjectSnapshot(
            file=performance_gate.FileSnapshot(
                path=fixture["proof"],
                data=forged_bytes,
                size=len(forged_bytes),
                sha256=hashlib.sha256(expected_proof).hexdigest(),
            ),
            value=forged_payload,
        )

        def final_json_snapshot(
            path: pathlib.Path,
            *,
            maximum: int,
            label: str,
        ) -> object:
            del maximum, label
            return budget_snapshot if path == fixture["budget"] else forged_snapshot

        with (
            mock.patch.object(
                performance_gate,
                "load_json_object_snapshot",
                side_effect=final_json_snapshot,
            ),
            mock.patch.object(
                performance_gate,
                "source_tree_digest",
                return_value=fixture["tree_digest"],
            ),
            mock.patch.object(performance_gate, "require_toolchain_unchanged"),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "performance proof content changed during proof emission",
            ),
        ):
            performance_gate.verify_emitted_collection(
                self.root,
                allow_dirty=True,
                tree_digest=fixture["tree_digest"],
                raw_path=fixture["raw"],
                raw_snapshot=raw_snapshot,
                proof_path=fixture["proof"],
                proof_payload=proof_payload,
                evidence_binary=fixture["binary"],
                binary_digest=hashlib.sha256(fixture["binary"].read_bytes()).hexdigest(),
                evidence_portable_archive=fixture["portable_archive"],
                portable_archive_digest=hashlib.sha256(
                    fixture["portable_archive"].read_bytes()
                ).hexdigest(),
                portable_source_digest=hashlib.sha256(
                    fixture["portable_source"].read_bytes()
                ).hexdigest(),
                budget_path=fixture["budget"],
                budget_snapshot=budget_snapshot,
                toolchain=fixture["toolchain"],
                cargo=pathlib.Path("/synthetic/toolchain/cargo"),
                rustc=pathlib.Path("/synthetic/toolchain/rustc"),
                clang=performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang",
                ar=performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar",
            )

    def test_full_verify_rejects_proof_and_artifact_tampering(self) -> None:
        cases = (
            ("manifest proof hash", "hash differs"),
            ("raw", "performance artifact changed"),
            ("binary", "performance artifact changed"),
            ("portable archive", "performance artifact changed"),
            ("portable source", "performance artifact changed"),
            ("budget", "performance artifact changed"),
            ("analysis", "performance proof analysis changed"),
            ("freshness", "performance proof is stale"),
            ("toolchain", "toolchain differs"),
            ("source", "source tree changed since performance proof"),
            ("dirty policy", "requires a clean source tree"),
        )
        for case, message in cases:
            with self.subTest(case=case):
                fixture = self.make_synthetic_proof(
                    manifest_bound=case == "manifest proof hash"
                )
                if case == "manifest proof hash":
                    fixture["proof"].write_bytes(
                        fixture["proof"].read_bytes() + b" "
                    )
                elif case == "raw":
                    lines = fixture["raw"].read_text(encoding="utf-8").splitlines()
                    index = self.record_line_index(
                        lines,
                        record_type="sample",
                        estimand=performance_gate.PROFILE_NON_REGRESSION,
                    )
                    record = json.loads(lines[index])
                    record["elapsed_ns_total"] += 1
                    lines[index] = json.dumps(record)
                    fixture["raw"].write_text(
                        "\n".join(lines) + "\n", encoding="utf-8"
                    )
                elif case == "binary":
                    fixture["binary"].write_bytes(
                        fixture["binary"].read_bytes() + b"tampered"
                    )
                elif case == "portable archive":
                    fixture["portable_archive"].write_bytes(
                        fixture["portable_archive"].read_bytes() + b"tampered"
                    )
                elif case == "portable source":
                    fixture["portable_source"].write_bytes(
                        fixture["portable_source"].read_bytes() + b"tampered"
                    )
                elif case == "budget":
                    budget = json.loads(
                        fixture["budget"].read_text(encoding="utf-8")
                    )
                    budget["max_block_median_cv"] = 0.04
                    fixture["budget"].write_text(
                        json.dumps(budget, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                elif case in ("analysis", "freshness", "toolchain"):
                    proof = json.loads(
                        fixture["proof"].read_text(encoding="utf-8")
                    )
                    if case == "analysis":
                        proof["analysis"][performance_gate.PROFILE_NON_REGRESSION][
                            "encapsulate"
                        ]["paired"][
                            "block_median_p50_ratio"
                        ] = 1.0
                    elif case == "freshness":
                        proof["generated_at"] = "2000-01-01T00:00:00Z"
                    else:
                        proof["toolchain"]["cargo"] = "cargo replaced"
                    fixture["proof"].write_text(
                        json.dumps(proof, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                elif case == "dirty policy":
                    fixture["args"].allow_dirty = False

                with self.assertRaisesRegex(performance_gate.GateError, message):
                    self.verify_synthetic_proof(
                        fixture,
                        tree_digest=(
                            "c" * 64 if case == "source" else None
                        ),
                    )

    def test_full_verify_rejects_c_toolchain_proof_mismatch(self) -> None:
        fixture = self.make_synthetic_proof(manifest_bound=False)
        proof = json.loads(fixture["proof"].read_text(encoding="utf-8"))
        proof["toolchain"]["clang"] = "Apple clang version proof-mismatch"
        fixture["proof"].write_text(
            json.dumps(proof, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "toolchain differs from current policy-bound toolchain",
        ):
            self.verify_synthetic_proof(fixture)

    def test_full_verify_detects_raw_toctou_after_snapshot(self) -> None:
        fixture = self.make_synthetic_proof(manifest_bound=False)
        original_analyse = performance_gate.analyse

        def analyse_then_replace_raw(*args: object, **kwargs: object) -> dict[str, object]:
            result = original_analyse(*args, **kwargs)
            fixture["raw"].write_bytes(fixture["raw"].read_bytes() + b"\n")
            return result

        with (
            mock.patch.object(
                performance_gate,
                "analyse",
                side_effect=analyse_then_replace_raw,
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "raw performance data changed during verification",
            ),
        ):
            self.verify_synthetic_proof(fixture)

    def test_full_verify_detects_proof_toctou_after_snapshot(self) -> None:
        fixture = self.make_synthetic_proof(manifest_bound=False)
        original_analyse = performance_gate.analyse

        def analyse_then_replace_proof(
            *args: object, **kwargs: object
        ) -> dict[str, object]:
            result = original_analyse(*args, **kwargs)
            fixture["proof"].write_bytes(fixture["proof"].read_bytes() + b" ")
            return result

        with (
            mock.patch.object(
                performance_gate,
                "analyse",
                side_effect=analyse_then_replace_proof,
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "selected performance proof changed during verification",
            ),
        ):
            self.verify_synthetic_proof(fixture)

    def test_point_and_upper_use_the_same_paired_block_estimand(self) -> None:
        result = self.parse_and_analyse()
        paired = result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
            "paired"
        ]
        for metric in ("p50_ratio", "p95_ratio", "p99_ratio", "p95_delta_ns"):
            point = paired[f"block_median_{metric}"]
            upper = paired[f"block_median_{metric}_upper_95"]
            self.assertGreaterEqual(upper, point)
        self.assertNotIn("p50_ratio", paired)
        self.assertIn(
            "p50_ratio",
            result[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "global_descriptive"
            ],
        )

    def test_small_common_drift_preserves_paired_estimand(self) -> None:
        baseline = self.parse_and_analyse()
        self.write_raw(common_drift=True)
        drifted = self.parse_and_analyse()
        self.assertAlmostEqual(
            baseline[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "paired"
            ]["block_median_p95_ratio"],
            drifted[performance_gate.PROFILE_NON_REGRESSION]["encapsulate"][
                "paired"
            ]["block_median_p95_ratio"],
        )

    def test_slow_common_drift_is_still_rejected_by_stability_gate(self) -> None:
        self.write_raw(slow_drift=True)
        with self.assertRaisesRegex(performance_gate.GateError, "INVALID_ENV"):
            self.parse_and_analyse()

    def test_batched_quantization_levels_do_not_masquerade_as_environment_drift(self) -> None:
        self.write_raw(quantized_combine=True)
        result = self.parse_and_analyse()
        self.assertLessEqual(
            result[performance_gate.PROFILE_NON_REGRESSION]["combine"][
                "max_block_median_cv"
            ],
            0.05,
        )

    def test_old_raw_and_proof_schemas_fail_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["schema_version"] = performance_gate.HARNESS_SCHEMA_VERSION - 1
        lines[0] = json.dumps(metadata)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "harness schema mismatch"):
            performance_gate.parse_raw(self.raw)
        with self.assertRaisesRegex(performance_gate.GateError, "performance proof schema mismatch"):
            performance_gate.validate_proof_schema(
                {"schema_version": performance_gate.PROOF_SCHEMA_VERSION - 1}
            )
        performance_gate.validate_proof_schema(
            {"schema_version": performance_gate.PROOF_SCHEMA_VERSION}
        )

    def test_profile_diagnostic_cannot_be_analysed_as_release_evidence(self) -> None:
        records = [
            json.loads(line)
            for line in self.raw.read_text(encoding="utf-8").splitlines()
        ]
        metadata = records[0]
        metadata["mode"] = performance_gate.PROFILE_DIAGNOSTIC_MODE
        metadata["target"] = "diagnostic-arm64"
        metadata[performance_gate.IMPLEMENTATION_IMPROVEMENT] = None
        records = [
            record
            for record in records
            if record.get("record_type") != "equivalence"
            and record.get("estimand")
            != performance_gate.IMPLEMENTATION_IMPROVEMENT
        ]
        self.raw.write_text(
            "".join(json.dumps(record) + "\n" for record in records),
            encoding="utf-8",
        )
        parsed_metadata, grouped = performance_gate.parse_raw(self.raw)
        self.assertEqual(
            parsed_metadata["mode"], performance_gate.PROFILE_DIAGNOSTIC_MODE
        )
        self.assertTrue(
            all(key[0] == performance_gate.PROFILE_NON_REGRESSION for key in grouped)
        )
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "metadata/budget mismatch for mode",
        ):
            performance_gate.analyse(parsed_metadata, grouped, self.budget)

    def test_implementation_equivalence_mismatch_fails_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="equivalence")
        record = json.loads(lines[index])
        record["portable_output_digest_hex"] = "c" * 64
        lines[index] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            performance_gate.GateError, "implementation outputs differ"
        ):
            performance_gate.parse_raw(self.raw)

    def test_missing_implementation_equivalence_case_fails_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(
            lines,
            record_type="equivalence",
            operation="encapsulate",
            ordinal=1,
        )
        del lines[index]
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "encapsulate equivalence case ids are not contiguous",
        ):
            performance_gate.parse_raw(self.raw)

    def test_implementation_contract_identity_and_scope_fail_closed(self) -> None:
        cases = (
            ("direction", "portable/native", "direction is invalid"),
            ("native_implementation_id", "unknown-native", "native identity is invalid"),
            (
                "portable_implementation_id",
                "product-portable",
                "portable identity is invalid",
            ),
            ("reference_scope", "shipping_backend", "not evidence-only"),
            ("product_profile", "CompatXWing", "ContextBound product path"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                self.write_raw()
                lines = self.raw.read_text(encoding="utf-8").splitlines()
                metadata = json.loads(lines[0])
                metadata[performance_gate.IMPLEMENTATION_IMPROVEMENT][field] = value
                lines[0] = json.dumps(metadata)
                self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(performance_gate.GateError, message):
                    performance_gate.parse_raw(self.raw)

    def test_all_environment_observations_must_remain_controlled(self) -> None:
        controlled = {
            "system": "Darwin",
            "release": "27.0.0",
            "machine": "arm64",
            "cpu": "Apple M1 Max",
            "thermal": "nominal",
            "ac_power": True,
            "controlled": True,
        }
        observations = {
            label: dict(controlled)
            for label in ("pre_build", "pre_run", "post_run", "post_analysis")
        }
        performance_gate.verify_environment_observations(observations, False)

        observations["post_run"] = {
            **controlled,
            "ac_power": False,
            "controlled": False,
        }
        with self.assertRaisesRegex(performance_gate.GateError, "INVALID_ENV"):
            performance_gate.verify_environment_observations(observations, False)

        observations["post_run"] = {**controlled, "cpu": "different"}
        with self.assertRaisesRegex(performance_gate.GateError, "changed for cpu"):
            performance_gate.verify_environment_observations(observations, False)

    def test_release_freshness_and_environment_policy_are_fixed(self) -> None:
        performance_gate.require_verification_policy(
            86400, allow_dirty=False, allow_uncontrolled=False
        )
        with self.assertRaisesRegex(performance_gate.GateError, "freshness to 86400"):
            performance_gate.require_verification_policy(
                604800, allow_dirty=False, allow_uncontrolled=False
            )
        with self.assertRaisesRegex(performance_gate.GateError, "requires --allow-dirty"):
            performance_gate.require_verification_policy(
                86400, allow_dirty=False, allow_uncontrolled=True
            )
        performance_gate.require_verification_policy(
            604800, allow_dirty=True, allow_uncontrolled=True
        )

    def test_environment_command_failure_is_not_silently_defaulted(self) -> None:
        with (
            mock.patch.object(performance_gate.platform, "system", return_value="Darwin"),
            mock.patch.object(
                performance_gate.subprocess,
                "check_output",
                side_effect=FileNotFoundError("missing sysctl"),
            ),
            self.assertRaisesRegex(performance_gate.GateError, "Darwin CPU identity"),
        ):
            performance_gate.collect_environment()

    def test_iterations_per_sample_tampering_fails_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["iterations_per_sample"]["combine"] = 1
        lines[0] = json.dumps(metadata)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "harness contract"):
            self.parse_and_analyse()

    def test_warmup_is_fixed_by_the_budget(self) -> None:
        self.budget["warmup_ms"] = 2
        with self.assertRaisesRegex(
            performance_gate.GateError, "metadata/budget mismatch for warmup_ms"
        ):
            self.parse_and_analyse()

        self.write_raw()
        self.budget["iterations_per_sample"]["combine"] = 1
        with self.assertRaisesRegex(performance_gate.GateError, "harness contract"):
            self.parse_and_analyse()

    def test_invalid_elapsed_total_fails_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="sample")
        record = json.loads(lines[index])
        record["elapsed_ns_total"] = 0
        lines[index] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "elapsed_ns_total must be positive"):
            performance_gate.parse_raw(self.raw)

        self.write_raw()
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="sample")
        record = json.loads(lines[index])
        record["elapsed_ns_total"] = performance_gate.MAX_EXACT_ELAPSED_NS_TOTAL + 1
        lines[index] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "exceeds exact analysis range"):
            performance_gate.parse_raw(self.raw)

    def test_pair_and_stability_block_configuration_fail_closed(self) -> None:
        self.budget["pair_block_size"] = 3
        with self.assertRaisesRegex(performance_gate.GateError, "complete ABBA"):
            self.parse_and_analyse()

        self.budget["pair_block_size"] = 4
        self.budget["stability_block_sizes"]["encapsulate"] = 3
        with self.assertRaisesRegex(performance_gate.GateError, "encapsulate stability block size"):
            self.parse_and_analyse()

        self.budget["stability_block_sizes"] = {"combine": 2, "encapsulate": 2}
        with self.assertRaisesRegex(performance_gate.GateError, "missing fields"):
            self.parse_and_analyse()

        with self.assertRaisesRegex(performance_gate.GateError, "multiple of corpus size"):
            performance_gate.validate_statistical_block_size(
                samples=20_480,
                corpus_size=64,
                block_size=96,
                label="test block size",
            )

        self.budget["stability_block_sizes"] = {
            "combine": 2,
            "encapsulate": 2,
            "decapsulate": 2,
        }
        self.budget["min_p99_tail_observations_per_pair_block"] = 2
        with self.assertRaisesRegex(performance_gate.GateError, "too few p99 tail observations"):
            self.parse_and_analyse()

        self.budget["stability_block_sizes"] = {"combine": 2, "encapsulate": 2, "decapsulate": 2}
        self.budget["min_p99_tail_observations_per_pair_block"] = 1
        self.budget["bootstrap_estimate_block_span"] = 3
        with self.assertRaisesRegex(performance_gate.GateError, "exceeds the paired estimate-block count"):
            self.parse_and_analyse()

        self.budget["bootstrap_estimate_block_span"] = 1
        self.budget["regression_guard_pair_block_size"] = 4
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "must be smaller than the primary",
        ):
            self.parse_and_analyse()

    def test_moving_block_bootstrap_is_deterministic_and_above_its_point(self) -> None:
        values = [1.0, 1.1, 1.2, 1.1, 1.3, 1.2, 1.4, 1.3]
        first = performance_gate.moving_block_bootstrap_median_upper(values, block_span=3)
        second = performance_gate.moving_block_bootstrap_median_upper(values, block_span=3)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first, performance_gate.percentile(values, 50))

    def test_nearest_rank_p99_tail_observation_count(self) -> None:
        self.assertEqual(performance_gate.percentile_tail_observation_count(256, 99), 3)
        self.assertEqual(performance_gate.percentile_tail_observation_count(1024, 99), 11)
        with self.assertRaisesRegex(performance_gate.GateError, "sample count must be positive"):
            performance_gate.percentile_tail_observation_count(0, 99)

    def test_old_budget_schema_fails_closed(self) -> None:
        self.budget["schema_version"] = performance_gate.BUDGET_SCHEMA_VERSION - 1
        with self.assertRaisesRegex(performance_gate.GateError, "budget schema mismatch"):
            self.parse_and_analyse()

    def test_budget_target_must_match_the_pinned_toolchain(self) -> None:
        self.budget["toolchain"]["target"] = "different-target"
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "budget target differs from toolchain target",
        ):
            self.parse_and_analyse()

    def test_moving_block_bootstrap_trend_sequence_is_deterministic_across_spans(self) -> None:
        values = [1.0 + 0.002 * index + 0.03 * ((index // 8) % 2) for index in range(80)]
        point = performance_gate.percentile(values, 50)
        for span in (1, 5, 10):
            with self.subTest(span=span):
                first = performance_gate.moving_block_bootstrap_median_upper(
                    values, block_span=span
                )
                second = performance_gate.moving_block_bootstrap_median_upper(
                    values, block_span=span
                )
                self.assertEqual(first, second)
                self.assertGreaterEqual(first, point)

    def test_production_budget_has_balanced_dual_scale_block_contracts(self) -> None:
        production = json.loads(
            (pathlib.Path(__file__).resolve().parent / "performance-budgets.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(production["min_samples_per_variant_operation"], 20_480)
        self.assertEqual(
            production["collection_samples_per_variant_operation"],
            20_480,
        )
        self.assertGreaterEqual(
            production["collection_samples_per_variant_operation"],
            production["min_samples_per_variant_operation"],
        )
        self.assertEqual(production["schema_version"], performance_gate.BUDGET_SCHEMA_VERSION)
        self.assertEqual(production["harness_schema_version"], performance_gate.HARNESS_SCHEMA_VERSION)
        self.assertEqual(production["mode"], performance_gate.RELEASE_EVIDENCE_MODE)
        self.assertEqual(production["target"], "aarch64-apple-darwin")
        self.assertEqual(production["pair_block_size"], 1024)
        self.assertEqual(production["regression_guard_pair_block_size"], 256)
        self.assertLess(
            production["regression_guard_pair_block_size"],
            production["pair_block_size"],
        )
        self.assertEqual(production["min_p99_tail_observations_per_pair_block"], 10)
        self.assertEqual(
            performance_gate.percentile_tail_observation_count(production["pair_block_size"], 99),
            11,
        )
        self.assertEqual(production["bootstrap_estimate_block_span"], 5)
        self.assertEqual(
            production["stability_block_sizes"],
            {"combine": 64, "encapsulate": 256, "decapsulate": 256},
        )
        self.assertEqual(production["iterations_per_sample"], performance_gate.EXPECTED_ITERATIONS_PER_SAMPLE)
        performance_gate.validate_toolchain_policy(production["toolchain"])
        self.assertEqual(
            production["toolchain"]["clang_path"],
            str(performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "clang"),
        )
        self.assertEqual(
            production["toolchain"]["ar_path"],
            str(performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN / "ar"),
        )
        self.assertEqual(
            production["toolchain"]["clang_version"],
            "Apple clang version 21.0.0 (clang-2100.1.1.101)",
        )
        self.assertEqual(production["toolchain"]["sdk_version"], "26.5")
        self.assertEqual(
            production["toolchain"]["sdk_path"],
            str(
                performance_gate.macos_sdk_path_for_toolchain(
                    performance_gate.XCODE_DEFAULT_TOOLCHAIN_BIN
                )
            ),
        )
        implementation = production[performance_gate.IMPLEMENTATION_IMPROVEMENT]
        self.assertEqual(implementation["direction"], "native/portable")
        self.assertEqual(
            implementation["native_implementation_id"],
            performance_gate.NATIVE_IMPLEMENTATION_ID,
        )
        self.assertEqual(
            implementation["portable_implementation_id"],
            performance_gate.PORTABLE_REFERENCE_IMPLEMENTATION_ID,
        )
        self.assertEqual(
            implementation["reference_scope"],
            performance_gate.PORTABLE_REFERENCE_SCOPE,
        )
        for operation in performance_gate.IMPLEMENTATION_OPERATIONS:
            self.assertEqual(
                implementation["operations"][operation],
                performance_gate.IMPLEMENTATION_IMPROVEMENT_LIMITS,
            )
        for block_size in {
            production["pair_block_size"],
            production["regression_guard_pair_block_size"],
            *production["stability_block_sizes"].values(),
        }:
            self.assertEqual(block_size % 2, 0)
            self.assertEqual(block_size % production["corpus_size"], 0)
            self.assertEqual(
                production["collection_samples_per_variant_operation"] % block_size,
                0,
            )

    def test_regression_guard_uses_the_same_numeric_limits(self) -> None:
        paired = {
            "block_median_p50_ratio_upper_95": 1.11,
            "block_median_p95_ratio_upper_95": 1.0,
            "block_median_p99_ratio_upper_95": 1.0,
            "block_median_p95_delta_ns_upper_95": 0.0,
        }
        with self.assertRaisesRegex(
            performance_gate.GateError,
            r"regression_guard\.block_median_p50_ratio_upper_95",
        ):
            performance_gate.enforce_operation_budget(
                "encapsulate",
                self.budget[performance_gate.PROFILE_NON_REGRESSION]["operations"][
                    "encapsulate"
                ],
                paired,
                "regression_guard",
            )

    def test_analyse_rejects_guard_failure_even_when_primary_scale_passes(self) -> None:
        self.budget["stability_block_sizes"]["encapsulate"] = 4
        self.write_raw(primary_pass_guard_fail=True)
        with self.assertRaisesRegex(
            performance_gate.GateError,
            r"BUDGET_FAIL profile_non_regression/encapsulate regression_guard\.",
        ):
            self.parse_and_analyse()

    def test_backend_mismatch_fails(self) -> None:
        self.budget[performance_gate.PROFILE_NON_REGRESSION]["backend"] = "different"
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "mismatch for profile_non_regression backend",
        ):
            self.parse_and_analyse()

    def test_schedule_mutation_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(
            lines,
            record_type="sample",
            estimand=performance_gate.PROFILE_NON_REGRESSION,
            operation="combine",
            variant="CompatXWing",
        )
        record = json.loads(lines[index])
        record["variant"] = "ContextBound"
        lines[index] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "duplicate paired sample|samples, expected"):
            performance_gate.parse_raw(self.raw)

    def test_schedule_pair_order_mutation_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        first_index = self.record_line_index(
            lines,
            record_type="sample",
            estimand=performance_gate.PROFILE_NON_REGRESSION,
            operation="combine",
            ordinal=0,
        )
        fourth_index = self.record_line_index(
            lines,
            record_type="sample",
            estimand=performance_gate.PROFILE_NON_REGRESSION,
            operation="combine",
            ordinal=3,
        )
        first = json.loads(lines[first_index])
        fourth = json.loads(lines[fourth_index])
        first["pair_id"], fourth["pair_id"] = fourth["pair_id"], first["pair_id"]
        first["corpus_index"], fourth["corpus_index"] = fourth["corpus_index"], first["corpus_index"]
        lines[first_index] = json.dumps(first)
        lines[fourth_index] = json.dumps(fourth)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "schedule cycle 0 is not ABBA/BAAB"):
            performance_gate.parse_raw(self.raw)

    def test_implementation_schedule_pair_order_mutation_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        first_index = self.record_line_index(
            lines,
            record_type="sample",
            estimand=performance_gate.IMPLEMENTATION_IMPROVEMENT,
            operation="encapsulate",
            ordinal=0,
        )
        fourth_index = self.record_line_index(
            lines,
            record_type="sample",
            estimand=performance_gate.IMPLEMENTATION_IMPROVEMENT,
            operation="encapsulate",
            ordinal=3,
        )
        first = json.loads(lines[first_index])
        fourth = json.loads(lines[fourth_index])
        first["pair_id"], fourth["pair_id"] = fourth["pair_id"], first["pair_id"]
        first["corpus_index"], fourth["corpus_index"] = (
            fourth["corpus_index"],
            first["corpus_index"],
        )
        lines[first_index] = json.dumps(first)
        lines[fourth_index] = json.dumps(fourth)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "implementation_improvement/encapsulate schedule cycle 0 is not ABBA/BAAB",
        ):
            performance_gate.parse_raw(self.raw)

    def test_odd_sample_count_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["samples_per_variant_operation"] = 3
        lines[0] = json.dumps(metadata)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "must be even"):
            performance_gate.parse_raw(self.raw)

    def test_noncanonical_metadata_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["application_context_hex"] = "ABC"
        lines[0] = json.dumps(metadata)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "invalid metadata application_context_hex"):
            performance_gate.parse_raw(self.raw)

    def test_missing_pair_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="sample")
        del lines[index]
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "samples, expected"):
            performance_gate.parse_raw(self.raw)

    def test_budget_regression_fails(self) -> None:
        self.write_raw(slow_bound=True)
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "BUDGET_FAIL profile_non_regression/encapsulate",
        ):
            self.parse_and_analyse()

    def test_native_not_materially_faster_fails_the_implementation_gate(self) -> None:
        self.write_raw(slow_native=True)
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "BUDGET_FAIL implementation_improvement/encapsulate",
        ):
            self.parse_and_analyse()

    def test_implementation_thresholds_are_preregistered_and_immutable(self) -> None:
        cases = (
            ("max_block_median_p50_ratio_upper_95", 0.951, 0.95),
            ("max_block_median_p95_ratio_upper_95", 0.94, 0.95),
            ("max_block_median_p99_ratio_upper_95", 1.01, 1.0),
        )
        operation_budget = self.budget[performance_gate.IMPLEMENTATION_IMPROVEMENT][
            "operations"
        ]["encapsulate"]
        for metric, replacement, expected in cases:
            with self.subTest(metric=metric):
                operation_budget[metric] = replacement
                with self.assertRaisesRegex(
                    performance_gate.GateError,
                    f"must remain preregistered at {expected}",
                ):
                    self.parse_and_analyse()
                operation_budget[metric] = expected

    def test_unstable_environment_fails(self) -> None:
        self.write_raw(unstable=True)
        with self.assertRaisesRegex(performance_gate.GateError, "INVALID_ENV"):
            self.parse_and_analyse()

    def test_unknown_budget_field_fails(self) -> None:
        self.budget["unexpected"] = True
        with self.assertRaisesRegex(performance_gate.GateError, "unknown fields"):
            self.parse_and_analyse()

    def test_missing_operation_metric_fails(self) -> None:
        del self.budget[performance_gate.PROFILE_NON_REGRESSION]["operations"][
            "encapsulate"
        ]["max_block_median_p99_ratio_upper_95"]
        with self.assertRaisesRegex(performance_gate.GateError, "is missing fields"):
            self.parse_and_analyse()

    def test_nonfinite_json_number_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="sample")
        record = json.loads(lines[index])
        record["elapsed_ns_total"] = float("nan")
        lines[index] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "non-finite JSON number"):
            performance_gate.parse_raw(self.raw)

    def test_duplicate_jsonl_keys_fail_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        index = self.record_line_index(lines, record_type="sample")
        lines[index] = lines[index][:-1] + ',"elapsed_ns_total":1}'
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "duplicate JSON key"):
            performance_gate.parse_raw(self.raw)

    def test_raw_hash_and_analysis_share_one_snapshot(self) -> None:
        snapshot, metadata, grouped = performance_gate.parse_raw_snapshot(self.raw)
        expected = hashlib.sha256(self.raw.read_bytes()).hexdigest()
        self.raw.write_text('{"replaced":true}\n', encoding="utf-8")
        self.assertEqual(snapshot.sha256, expected)
        analysis = performance_gate.analyse(metadata, grouped, self.budget)
        self.assertIn(
            "encapsulate", analysis[performance_gate.PROFILE_NON_REGRESSION]
        )

    def test_release_budget_path_is_fixed_even_for_identical_content(self) -> None:
        artifact = self.root / "artifact"
        artifact.mkdir()
        canonical = artifact / "performance-budgets.json"
        content = json.dumps(self.budget, sort_keys=True) + "\n"
        canonical.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode()).hexdigest()
        artifacts = {
            "budget_path": "artifact/performance-budgets.json",
            "budget_sha256": digest,
        }
        snapshot = performance_gate.verified_production_budget_snapshot(
            self.root, artifacts
        )
        self.assertEqual(snapshot.file.sha256, digest)

        alternate = self.root / "target" / "lenient-budget.json"
        alternate.parent.mkdir()
        alternate.write_text(content, encoding="utf-8")
        artifacts["budget_path"] = "target/lenient-budget.json"
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "must use artifact/performance-budgets.json",
        ):
            performance_gate.verified_production_budget_snapshot(
                self.root, artifacts
            )

        artifacts["budget_path"] = "artifact/performance-budgets.json"
        target = artifact / "budget-target.json"
        canonical.rename(target)
        canonical.symlink_to(target)
        with self.assertRaisesRegex(performance_gate.GateError, "cannot safely open"):
            performance_gate.verified_production_budget_snapshot(
                self.root, artifacts
            )

    def test_boolean_budget_is_not_numeric(self) -> None:
        self.budget[performance_gate.PROFILE_NON_REGRESSION]["operations"][
            "combine"
        ]["max_block_median_p95_delta_ns_upper_95"] = True
        with self.assertRaisesRegex(performance_gate.GateError, "must be a number"):
            self.parse_and_analyse()

    def test_proof_paths_must_be_distinct(self) -> None:
        same = self.root / "same"
        with self.assertRaisesRegex(performance_gate.GateError, "must be distinct"):
            performance_gate.require_distinct_paths({"raw": same, "proof": same})

    def test_host_target_is_explicit(self) -> None:
        target = performance_gate.host_target(pathlib.Path.cwd())
        self.assertTrue(target)
        self.assertNotIn("/", target)
        self.assertNotIn("\\", target)

    def test_c_toolchain_policy_fields_fail_closed(self) -> None:
        valid = dict(self.budget["toolchain"])
        missing = dict(valid)
        del missing["ar_sha256"]
        extra = dict(valid, unexpected="value")
        bad_hash = dict(valid, clang_sha256="not-a-sha256")
        bad_version = dict(valid, clang_version="clang\nsecond line")
        bad_path = dict(valid, clang_path="/usr/bin/clang")
        bad_sdk_hash = dict(valid, sdk_settings_sha256="not-a-sha256")
        bad_sdk_path = dict(valid, sdk_path="/tmp/MacOSX.sdk")
        escaped_path = dict(
            valid,
            ar_path=(
                "/Applications/Xcode.app/Contents/Developer/Toolchains/"
                "XcodeDefault.xctoolchain/usr/bin/../bin/ar"
            ),
        )
        cases = (
            (missing, "missing fields"),
            (extra, "unknown fields"),
            (bad_hash, "clang_sha256 is malformed"),
            (bad_version, "clang_version must be a non-empty single line"),
            (bad_path, "must be the pinned Xcode clang executable"),
            (bad_sdk_hash, "sdk_settings_sha256 is malformed"),
            (bad_sdk_path, "must name the pinned macOS SDK"),
            (escaped_path, "is not a canonical absolute path"),
        )
        for policy, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                performance_gate.GateError, message
            ):
                performance_gate.validate_toolchain_policy(policy)

    def test_c_toolchain_proof_fields_fail_closed(self) -> None:
        valid = self.proof_toolchain_identity()
        missing = dict(valid)
        del missing["clang_path"]
        extra = dict(valid, unexpected="value")
        bad_hash = dict(valid, ar_sha256="0" * 63)
        bad_version = dict(valid, clang="clang\nsecond line")
        bad_path = dict(valid, ar_path="/usr/bin/ar")
        bad_sdk_hash = dict(valid, sdk_settings_sha256="0" * 63)
        cases = (
            (missing, "missing fields"),
            (extra, "unknown fields"),
            (bad_hash, "ar_sha256 is malformed"),
            (bad_version, "performance toolchain clang must be a non-empty single line"),
            (bad_path, "must be the pinned Xcode ar executable"),
            (bad_sdk_hash, "sdk_settings_sha256 is malformed"),
        )
        for identity, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                performance_gate.GateError, message
            ):
                performance_gate.validate_toolchain_identity(identity)

    def test_toolchain_policy_ignores_path_injected_executable_before_running(self) -> None:
        fake_cargo = self.root / "cargo"
        fake_rustc = self.root / "rustc"
        for path in (fake_cargo, fake_rustc):
            path.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            path.chmod(0o700)
        account_home = self.root / "account"
        cargo, rustc, clang, ar, policy, command_output = self.synthetic_toolchain(
            account_home, "test-pinned"
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(
                performance_gate.shutil,
                "which",
                side_effect=lambda name: str(
                    fake_cargo if name == "cargo" else fake_rustc
                ),
            ) as which,
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            mock.patch.object(
                performance_gate,
                "run_line",
                side_effect=command_output,
            ),
        ):
            (
                _identity,
                selected_cargo,
                selected_rustc,
                selected_clang,
                selected_ar,
            ) = performance_gate.verified_toolchain(self.root, self.budget)
        which.assert_not_called()
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)
        self.assertEqual(selected_clang, clang)
        self.assertEqual(selected_ar, ar)

    def test_toolchain_policy_rejects_rustup_parent_symlink(self) -> None:
        account_home = self.root / "account"
        account_home.mkdir()
        outside_rustup = self.root / "outside-rustup"
        tool_bin = outside_rustup / "toolchains" / "test-pinned" / "bin"
        tool_bin.mkdir(parents=True)
        for name, content in (("cargo", b"cargo"), ("rustc", b"rustc")):
            path = tool_bin / name
            path.write_bytes(content)
            path.chmod(0o700)
        (account_home / ".rustup").symlink_to(outside_rustup, target_is_directory=True)
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "performance rustup home is missing or unsafe",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_selects_same_directory_hash_matched_pair(self) -> None:
        account_home = self.root / "account"
        cargo, rustc, clang, ar, policy, command_output = self.synthetic_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))

        with (
            mock.patch.object(performance_gate.shutil, "which", return_value=None),
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            mock.patch.object(performance_gate, "run_line", side_effect=command_output),
        ):
            (
                identity,
                selected_cargo,
                selected_rustc,
                selected_clang,
                selected_ar,
            ) = performance_gate.verified_toolchain(self.root, self.budget)
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)
        self.assertEqual(selected_clang, clang)
        self.assertEqual(selected_ar, ar)
        self.assertEqual(identity["target"], "aarch64-test-target")

    def test_toolchain_policy_ignores_identical_unselected_rustup_alias(self) -> None:
        account_home = self.root / "account"
        toolchains = account_home / ".rustup" / "toolchains"
        cargo, rustc, clang, ar, policy, command_output = self.synthetic_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        stable_bin = toolchains / "stable-aarch64-test-target" / "bin"
        stable_bin.mkdir(parents=True)
        for name, content in (("cargo", b"cargo"), ("rustc", b"rustc")):
            path = stable_bin / name
            path.write_bytes(content)
            path.chmod(0o700)
        account = types.SimpleNamespace(pw_dir=str(account_home))

        with (
            mock.patch.object(performance_gate.shutil, "which", return_value=None),
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            mock.patch.object(performance_gate, "run_line", side_effect=command_output),
        ):
            (
                identity,
                selected_cargo,
                selected_rustc,
                selected_clang,
                selected_ar,
            ) = performance_gate.verified_toolchain(self.root, self.budget)
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)
        self.assertEqual(selected_clang, clang)
        self.assertEqual(selected_ar, ar)
        self.assertEqual(identity["cargo_path"], str(cargo))

    def test_toolchain_policy_rejects_unsafe_rustup_toolchain_name(self) -> None:
        self.budget["toolchain"]["rustup_toolchain"] = "../outside"
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "toolchain policy rustup_toolchain is malformed",
        ):
            performance_gate.validate_toolchain_policy(self.budget["toolchain"])

    def test_toolchain_policy_rejects_selected_executable_symlink(self) -> None:
        account_home = self.root / "account"
        cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        cargo.unlink()
        outside_cargo = self.root / "outside-cargo"
        outside_cargo.write_bytes(b"cargo")
        outside_cargo.chmod(0o700)
        cargo.symlink_to(outside_cargo)
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance cargo executable is missing or unsafe",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_rejects_xcode_executable_symlink(self) -> None:
        account_home = self.root / "account"
        _cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        outside_clang = self.root / "outside-clang"
        outside_clang.write_bytes(b"clang")
        outside_clang.chmod(0o700)
        clang.unlink()
        clang.symlink_to(outside_clang)
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance clang executable is missing or unsafe",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_four_tool_revalidation_rejects_xcode_tool_replacement(self) -> None:
        account_home = self.root / "account"
        cargo, rustc, clang, ar, policy, command_output = self.synthetic_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            mock.patch.object(performance_gate, "run_line", side_effect=command_output),
        ):
            identity, cargo, rustc, clang, ar = performance_gate.verified_toolchain(
                self.root, self.budget
            )
            ar.write_bytes(b"replaced ar")
            with self.assertRaisesRegex(
                performance_gate.GateError,
                "ar executable changed during performance evidence processing",
            ):
                performance_gate.require_toolchain_unchanged(
                    self.root, identity, cargo, rustc, clang, ar
                )

    def test_toolchain_policy_rejects_hash_mismatch(self) -> None:
        account_home = self.root / "account"
        cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        cargo.write_bytes(b"changed cargo")
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance cargo executable differs from toolchain policy",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_rejects_xcode_hash_mismatch(self) -> None:
        account_home = self.root / "account"
        _cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        clang.write_bytes(b"changed clang")
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance clang executable differs from toolchain policy",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_rejects_sdk_settings_mismatch(self) -> None:
        account_home = self.root / "account"
        _cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        settings = pathlib.Path(policy["sdk_path"]) / performance_gate.MACOS_SDK_SETTINGS_NAME
        settings.write_bytes(b'{"Version":"changed-sdk"}')
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "macOS SDK version differs from performance policy",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_reports_candidate_disappearance(self) -> None:
        account_home = self.root / "account"
        _cargo, _rustc, clang, _ar, policy, _command_output = self.synthetic_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(
                performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
            ),
            mock.patch.object(
                performance_gate,
                "sha256_file",
                side_effect=FileNotFoundError("toolchain changed"),
            ),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "cannot inspect pinned performance cargo executable",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_rejects_version_and_target_mismatch(self) -> None:
        account_home = self.root / "account"
        cargo, rustc, clang, _ar, policy, command_output = self.synthetic_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))

        def wrong_cargo_version(
            args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            if args == [str(cargo), "--version"]:
                return "cargo wrong"
            return command_output(args, cwd, environment=environment)

        def wrong_rustc_version(
            args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            if args == [str(rustc), "--version"]:
                return "rustc wrong"
            return command_output(args, cwd, environment=environment)

        def wrong_clang_version(
            args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            if args == [str(clang), "--version"]:
                return "Apple clang version wrong"
            return command_output(args, cwd, environment=environment)

        def wrong_target(
            args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            if args == [str(rustc), "-vV"]:
                return "host: wrong-target"
            return command_output(args, cwd, environment=environment)

        cases = (
            (wrong_cargo_version, "cargo version differs from performance policy"),
            (wrong_rustc_version, "rustc version differs from performance policy"),
            (wrong_clang_version, "clang version differs from performance policy"),
            (wrong_target, "rustc target differs from performance policy"),
        )
        for output, message in cases:
            with (
                self.subTest(message=message),
                mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
                mock.patch.object(
                    performance_gate, "XCODE_DEFAULT_TOOLCHAIN_BIN", clang.parent
                ),
                mock.patch.object(performance_gate, "run_line", side_effect=output),
                self.assertRaisesRegex(performance_gate.GateError, message),
            ):
                performance_gate.verified_toolchain(self.root, self.budget)

    def test_hardened_cargo_environment_does_not_inherit_injection_controls(self) -> None:
        account_home = self.root / "account"
        cargo_home = account_home / ".cargo"
        cargo_home.mkdir(parents=True)
        private = self.root / "private"
        private.mkdir()
        sdk = self.root / "trusted-sdk"
        sdk.mkdir()
        sdk = sdk.resolve()
        target = private / "cargo-target"
        target.mkdir()
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with mock.patch.object(
            performance_gate.pwd, "getpwuid", return_value=account
        ):
            environment = performance_gate.hardened_cargo_environment(
                self.root,
                pathlib.Path("/trusted/cargo"),
                pathlib.Path("/trusted/rustc"),
                pathlib.Path("/trusted/Xcode/clang"),
                pathlib.Path("/trusted/Xcode/ar"),
                sdk,
                "aarch64-apple-darwin",
                target,
                private,
            )
        for forbidden in (
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ):
            self.assertNotIn(forbidden, environment)
        self.assertEqual(environment["RUSTC"], "/trusted/rustc")
        self.assertEqual(environment["CC"], "/trusted/Xcode/clang")
        self.assertEqual(environment["AR"], "/trusted/Xcode/ar")
        self.assertEqual(environment["SDKROOT"], str(sdk))
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(target))
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(
            environment["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"],
            "/trusted/Xcode/clang",
        )

    def test_evidence_harness_link_contract_is_private_and_fixed(self) -> None:
        archive = self.root / "libqperiapt_mlkem_portable_evidence.a"
        archive.write_bytes(b"portable archive")
        base = {"PATH": "/trusted/bin"}
        environment = performance_gate.performance_harness_environment(
            base,
            target="aarch64-apple-darwin",
            portable_archive=archive,
        )
        self.assertEqual(base, {"PATH": "/trusted/bin"})
        self.assertEqual(
            environment["QPERIAPT_PERFORMANCE_TARGET"], "aarch64-apple-darwin"
        )
        self.assertEqual(
            environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"),
            [
                "--cfg",
                "qperiapt_performance_evidence",
                "-L",
                f"native={archive.parent}",
                "-l",
                f"static={performance_gate.PORTABLE_REFERENCE_ARCHIVE_STEM}",
            ],
        )
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "requires aarch64-apple-darwin",
        ):
            performance_gate.performance_harness_environment(
                base,
                target="x86_64-unknown-linux-gnu",
                portable_archive=archive,
            )
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "already contains Rust flags",
        ):
            performance_gate.performance_harness_environment(
                {"RUSTFLAGS": "--cfg injected"},
                target="aarch64-apple-darwin",
                portable_archive=archive,
            )

    def test_hardened_cargo_environment_rejects_ancestor_configuration(self) -> None:
        account_home = self.root / "account"
        (account_home / ".cargo").mkdir(parents=True)
        repository = self.root / "parent" / "repository"
        repository.mkdir(parents=True)
        ancestor_config = self.root / "parent" / ".cargo" / "config.toml"
        ancestor_config.parent.mkdir()
        ancestor_config.write_text("[build]\nrustflags = []\n", encoding="utf-8")
        private = self.root / "private-ancestor"
        private.mkdir()
        sdk = self.root / "trusted-sdk-ancestor"
        sdk.mkdir()
        sdk = sdk.resolve()
        target = private / "cargo-target"
        target.mkdir()
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            self.assertRaisesRegex(
                performance_gate.GateError, "rejects Cargo configuration"
            ),
        ):
            performance_gate.hardened_cargo_environment(
                repository,
                pathlib.Path("/trusted/cargo"),
                pathlib.Path("/trusted/rustc"),
                pathlib.Path("/trusted/Xcode/clang"),
                pathlib.Path("/trusted/Xcode/ar"),
                sdk,
                "aarch64-apple-darwin",
                target,
                private,
            )

    def test_collection_resource_limits_fail_closed(self) -> None:
        self.assertEqual(
            performance_gate.collection_parameters_from_budget(self.budget),
            (8, 1),
        )
        for field, value, message in (
            (
                "collection_samples_per_variant_operation",
                performance_gate.MAX_COLLECTION_SAMPLES + 1,
                "sample count exceeds",
            ),
            (
                "warmup_ms",
                performance_gate.MAX_COLLECTION_WARMUP_MS + 1,
                "warmup exceeds",
            ),
        ):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(self.budget))
                changed[field] = value
                with self.assertRaisesRegex(performance_gate.GateError, message):
                    performance_gate.collection_parameters_from_budget(changed)

    def test_minimum_and_exact_collection_samples_have_distinct_roles(self) -> None:
        changed = json.loads(json.dumps(self.budget))
        changed["min_samples_per_variant_operation"] = 4
        self.assertEqual(
            performance_gate.collection_parameters_from_budget(changed),
            (8, 1),
        )

        changed["min_samples_per_variant_operation"] = 8
        changed["collection_samples_per_variant_operation"] = 4
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "invalid exact collection sample budget",
        ):
            performance_gate.collection_parameters_from_budget(changed)

        changed = json.loads(json.dumps(self.budget))
        changed["collection_samples_per_variant_operation"] = 16
        metadata, _grouped = performance_gate.parse_raw(self.raw)
        with self.assertRaisesRegex(
            performance_gate.GateError,
            "differs from the preregistered exact collection policy",
        ):
            performance_gate.validate_budget(metadata, changed)

    def test_collection_policy_rejects_representative_malformed_budget_before_use(
        self,
    ) -> None:
        missing = object()
        mutations = (
            (
                "missing-exact-samples",
                ("collection_samples_per_variant_operation",),
                missing,
            ),
            ("null-corpus", ("corpus_size",), None),
            ("zero-corpus", ("corpus_size",), 0),
            (
                "alternate-target",
                ("target",),
                "x86_64-apple-darwin",
            ),
            (
                "alternate-toolchain-target",
                ("toolchain", "target"),
                "x86_64-apple-darwin",
            ),
            (
                "empty-backend",
                (performance_gate.PROFILE_NON_REGRESSION, "backend"),
                "",
            ),
            (
                "nonnumeric-profile-limit",
                (
                    performance_gate.PROFILE_NON_REGRESSION,
                    "operations",
                    "encapsulate",
                    "max_block_median_p95_ratio_upper_95",
                ),
                "1.15",
            ),
            (
                "zero-profile-limit",
                (
                    performance_gate.PROFILE_NON_REGRESSION,
                    "operations",
                    "encapsulate",
                    "max_block_median_p95_ratio_upper_95",
                ),
                0,
            ),
        )
        for label, path, replacement in mutations:
            with self.subTest(label=label):
                changed = json.loads(json.dumps(self.budget))
                parent = changed
                for component in path[:-1]:
                    parent = parent[component]
                if replacement is missing:
                    del parent[path[-1]]
                else:
                    parent[path[-1]] = replacement
                with self.assertRaises(performance_gate.GateError):
                    performance_gate.collection_parameters_from_budget(changed)

    def test_release_collector_cli_has_no_runtime_policy_overrides(self) -> None:
        for option, value in (("--samples", "8"), ("--warmup-ms", "1")):
            with self.subTest(option=option):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        performance_gate.sys,
                        "argv",
                        [
                            "performance_gate.py",
                            "collect",
                            "--root",
                            ".",
                            "--raw",
                            "target/performance/raw.jsonl",
                            "--proof",
                            "target/performance/proof.json",
                            option,
                            value,
                        ],
                    ),
                    mock.patch.object(performance_gate.sys, "stderr", stderr),
                    self.assertRaises(SystemExit) as raised,
                ):
                    performance_gate.main()
                self.assertEqual(2, raised.exception.code)
                self.assertIn(f"unrecognized arguments: {option} {value}", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
