from __future__ import annotations

import argparse
import hashlib
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
            "schema_version": 5,
            "harness_schema_version": 2,
            "backend": "matched-test-backend",
            "schedule": "ABBA/BAAB",
            "corpus_size": 2,
            "iterations_per_sample": {
                "combine": 256,
                "encapsulate": 1,
                "decapsulate": 2,
            },
            "min_samples_per_profile_operation": 8,
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
                "cargo_sha256": "1" * 64,
                "cargo_version": "cargo test",
                "rustc_sha256": "2" * 64,
                "rustc_version": "rustc test",
                "rustup_toolchain": "test-pinned",
                "target": "test-target",
            },
            "operations": {
                "combine": {"max_block_median_p95_delta_ns_upper_95": 10000},
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
    ) -> None:
        metadata = {
            "schema_version": 2,
            "record_type": "metadata",
            "backend": "matched-test-backend",
            "schedule": "ABBA/BAAB",
            "corpus_size": 2,
            "samples_per_profile_operation": 8,
            "iterations_per_sample": {
                "combine": 256,
                "encapsulate": 1,
                "decapsulate": 2,
            },
            "warmup_ms": 1,
            "suite_id_hex": "00",
            "policy_version": 1,
            "application_context_hex": "01",
        }
        records = [metadata]
        for operation in performance_gate.OPERATIONS:
            schedule: list[tuple[str, int]] = []
            for cycle in range(metadata["samples_per_profile_operation"] // 2):
                first_pair = cycle * 2
                schedule.extend(
                    [
                        ("ContextBound", first_pair),
                        ("CompatXWing", first_pair),
                        ("CompatXWing", first_pair + 1),
                        ("ContextBound", first_pair + 1),
                    ]
                    if cycle % 2 == 0
                    else [
                        ("CompatXWing", first_pair),
                        ("ContextBound", first_pair),
                        ("ContextBound", first_pair + 1),
                        ("CompatXWing", first_pair + 1),
                    ]
                )
            for schedule_index, (profile, pair_id) in enumerate(schedule):
                compat = 500 if operation == "combine" else 100_000
                bound = 5_500 if operation == "combine" else 105_000
                elapsed = bound if profile == "ContextBound" else compat
                if slow_bound and operation == "encapsulate" and profile == "ContextBound":
                    elapsed = 140_000
                if primary_pass_guard_fail and operation == "encapsulate":
                    slow_guard_half = pair_id % 4 < 2
                    elapsed = (
                        140_000
                        if (profile == "ContextBound") == slow_guard_half
                        else 100_000
                    )
                iterations = metadata["iterations_per_sample"][operation]
                elapsed_ns_total = elapsed * iterations
                if quantized_combine and operation == "combine" and profile == "CompatXWing":
                    elapsed_ns_total = 334 * iterations + (41 if pair_id >= 2 else 0)
                if common_drift:
                    elapsed_ns_total = elapsed_ns_total * (100 + pair_id) // 100
                if slow_drift:
                    elapsed_ns_total = elapsed_ns_total * (100 + 20 * pair_id) // 100
                if unstable and pair_id >= 2:
                    elapsed_ns_total *= 2
                records.append(
                    {
                        "schema_version": 2,
                        "record_type": "sample",
                        "operation": operation,
                        "profile": profile,
                        "pair_id": pair_id,
                        "schedule_index": schedule_index,
                        "corpus_index": pair_id % 2,
                        "elapsed_ns_total": elapsed_ns_total,
                    }
                )
        self.raw.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

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

    def synthetic_rustup_toolchain(
        self, account_home: pathlib.Path, name: str = "pinned"
    ) -> tuple[
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
        policy = {
            "cargo_sha256": hashlib.sha256(b"cargo").hexdigest(),
            "cargo_version": "cargo pinned",
            "rustc_sha256": hashlib.sha256(b"rustc").hexdigest(),
            "rustc_version": "rustc pinned",
            "rustup_toolchain": name,
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
            if args == [str(rustc), "-vV"]:
                return "host: aarch64-test-target"
            self.fail(f"unexpected command: {args}")

        return cargo, rustc, policy, command_output

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
            / "test-target"
            / f"paired_profile_perf-{binary_digest}"
        )
        binary_path.parent.mkdir(parents=True, exist_ok=True)
        binary_path.write_bytes(binary_bytes)
        binary_path.chmod(0o700)

        metadata, grouped = performance_gate.parse_raw(raw_path)
        analysis = performance_gate.analyse(metadata, grouped, self.budget)
        environment = {
            label: self.controlled_environment()
            for label in ("pre_build", "pre_run", "post_run", "post_analysis")
        }
        tree_digest = "a" * 64
        toolchain = {
            "cargo": "cargo test",
            "cargo_path": "/synthetic/toolchain/cargo",
            "cargo_sha256": "1" * 64,
            "rustc": "rustc test",
            "rustc_path": "/synthetic/toolchain/rustc",
            "rustc_sha256": "2" * 64,
            "target": "test-target",
        }
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
            result["encapsulate"]["paired"]["block_median_p50_ratio_upper_95"],
            1.10,
        )
        self.assertEqual(result["encapsulate"]["pair_block_size"], 4)
        self.assertEqual(
            result["encapsulate"]["regression_guard_pair_block_size"], 2
        )
        self.assertLessEqual(
            result["encapsulate"]["regression_guard_paired"][
                "block_median_p50_ratio_upper_95"
            ],
            1.10,
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
        toolchain = {
            "cargo": "cargo test",
            "cargo_path": "/synthetic/toolchain/cargo",
            "cargo_sha256": "1" * 64,
            "rustc": "rustc test",
            "rustc_path": "/synthetic/toolchain/rustc",
            "rustc_sha256": "2" * 64,
            "target": "test-target",
        }
        binary_bytes = b"fresh synthetic collector binary"

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

        def fake_run(command: list[str], **_kwargs: object) -> object:
            output = pathlib.Path(command[command.index("--raw-out") + 1])
            output.write_bytes(self.raw.read_bytes())
            return types.SimpleNamespace(returncode=0)

        collect_args = types.SimpleNamespace(
            root=self.root.resolve(),
            raw=raw_path.resolve(),
            proof=proof_path.resolve(),
            samples=8,
            warmup_ms=1,
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
                ),
            ),
            mock.patch.object(
                performance_gate, "hardened_cargo_environment", return_value={}
            ),
            mock.patch.object(performance_gate, "build_harness", side_effect=fake_build),
            mock.patch.object(performance_gate.subprocess, "run", side_effect=fake_run),
            mock.patch.object(performance_gate, "require_toolchain_unchanged"),
            mock.patch.object(performance_gate, "git_commit", return_value="b" * 40),
            mock.patch.object(performance_gate, "source_tree_dirty", return_value=True),
        ):
            performance_gate.collect(collect_args)

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
            "proof": proof_path,
            "tree_digest": tree_digest,
            "toolchain": toolchain,
            "environment": controlled,
        }
        self.assertEqual(raw_path.read_bytes(), self.raw.read_bytes())
        self.verify_synthetic_proof(fixture)

    def test_full_verify_rejects_proof_and_artifact_tampering(self) -> None:
        cases = (
            ("manifest proof hash", "hash differs"),
            ("raw", "performance artifact changed"),
            ("binary", "performance artifact changed"),
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
                    record = json.loads(lines[1])
                    record["elapsed_ns_total"] += 1
                    lines[1] = json.dumps(record)
                    fixture["raw"].write_text(
                        "\n".join(lines) + "\n", encoding="utf-8"
                    )
                elif case == "binary":
                    fixture["binary"].write_bytes(
                        fixture["binary"].read_bytes() + b"tampered"
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
                        proof["analysis"]["encapsulate"]["paired"][
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
        paired = result["encapsulate"]["paired"]
        for metric in ("p50_ratio", "p95_ratio", "p99_ratio", "p95_delta_ns"):
            point = paired[f"block_median_{metric}"]
            upper = paired[f"block_median_{metric}_upper_95"]
            self.assertGreaterEqual(upper, point)
        self.assertNotIn("p50_ratio", paired)
        self.assertIn("p50_ratio", result["encapsulate"]["global_descriptive"])

    def test_small_common_drift_preserves_paired_estimand(self) -> None:
        baseline = self.parse_and_analyse()
        self.write_raw(common_drift=True)
        drifted = self.parse_and_analyse()
        self.assertAlmostEqual(
            baseline["encapsulate"]["paired"]["block_median_p95_ratio"],
            drifted["encapsulate"]["paired"]["block_median_p95_ratio"],
        )

    def test_slow_common_drift_is_still_rejected_by_stability_gate(self) -> None:
        self.write_raw(slow_drift=True)
        with self.assertRaisesRegex(performance_gate.GateError, "INVALID_ENV"):
            self.parse_and_analyse()

    def test_batched_quantization_levels_do_not_masquerade_as_environment_drift(self) -> None:
        self.write_raw(quantized_combine=True)
        result = self.parse_and_analyse()
        self.assertLessEqual(result["combine"]["max_block_median_cv"], 0.05)

    def test_old_raw_and_proof_schemas_fail_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["schema_version"] = 1
        lines[0] = json.dumps(metadata)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "harness schema mismatch"):
            performance_gate.parse_raw(self.raw)
        with self.assertRaisesRegex(performance_gate.GateError, "performance proof schema mismatch"):
            performance_gate.validate_proof_schema({"schema_version": 3})
        performance_gate.validate_proof_schema({"schema_version": 4})

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
        record = json.loads(lines[1])
        record["elapsed_ns_total"] = 0
        lines[1] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "elapsed_ns_total must be positive"):
            performance_gate.parse_raw(self.raw)

        self.write_raw()
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        record["elapsed_ns_total"] = performance_gate.MAX_EXACT_ELAPSED_NS_TOTAL + 1
        lines[1] = json.dumps(record)
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
        self.assertEqual(production["min_samples_per_profile_operation"], 20_480)
        self.assertEqual(production["schema_version"], performance_gate.BUDGET_SCHEMA_VERSION)
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
        for block_size in {
            production["pair_block_size"],
            production["regression_guard_pair_block_size"],
            *production["stability_block_sizes"].values(),
        }:
            self.assertEqual(block_size % 2, 0)
            self.assertEqual(block_size % production["corpus_size"], 0)
            self.assertEqual(production["min_samples_per_profile_operation"] % block_size, 0)

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
                self.budget["operations"]["encapsulate"],
                paired,
                "regression_guard",
            )

    def test_analyse_rejects_guard_failure_even_when_primary_scale_passes(self) -> None:
        self.budget["stability_block_sizes"]["encapsulate"] = 4
        self.write_raw(primary_pass_guard_fail=True)
        with self.assertRaisesRegex(
            performance_gate.GateError,
            r"BUDGET_FAIL encapsulate regression_guard\.",
        ):
            self.parse_and_analyse()

    def test_backend_mismatch_fails(self) -> None:
        self.budget["backend"] = "different"
        with self.assertRaisesRegex(performance_gate.GateError, "mismatch for backend"):
            self.parse_and_analyse()

    def test_schedule_mutation_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[2])
        record["profile"] = "ContextBound"
        lines[2] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "duplicate paired sample|samples, expected"):
            performance_gate.parse_raw(self.raw)

    def test_schedule_pair_order_mutation_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[1])
        fourth = json.loads(lines[4])
        first["pair_id"], fourth["pair_id"] = fourth["pair_id"], first["pair_id"]
        first["corpus_index"], fourth["corpus_index"] = fourth["corpus_index"], first["corpus_index"]
        lines[1] = json.dumps(first)
        lines[4] = json.dumps(fourth)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "schedule cycle 0 is not ABBA/BAAB"):
            performance_gate.parse_raw(self.raw)

    def test_odd_sample_count_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        metadata = json.loads(lines[0])
        metadata["samples_per_profile_operation"] = 3
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
        del lines[2]
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "samples, expected"):
            performance_gate.parse_raw(self.raw)

    def test_budget_regression_fails(self) -> None:
        self.write_raw(slow_bound=True)
        with self.assertRaisesRegex(performance_gate.GateError, "BUDGET_FAIL encapsulate"):
            self.parse_and_analyse()

    def test_unstable_environment_fails(self) -> None:
        self.write_raw(unstable=True)
        with self.assertRaisesRegex(performance_gate.GateError, "INVALID_ENV"):
            self.parse_and_analyse()

    def test_unknown_budget_field_fails(self) -> None:
        self.budget["unexpected"] = True
        with self.assertRaisesRegex(performance_gate.GateError, "unknown fields"):
            self.parse_and_analyse()

    def test_missing_operation_metric_fails(self) -> None:
        del self.budget["operations"]["encapsulate"]["max_block_median_p99_ratio_upper_95"]
        with self.assertRaisesRegex(performance_gate.GateError, "metric inventory mismatch"):
            self.parse_and_analyse()

    def test_nonfinite_json_number_fails(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[1])
        record["elapsed_ns_total"] = float("nan")
        lines[1] = json.dumps(record)
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "non-finite JSON number"):
            performance_gate.parse_raw(self.raw)

    def test_duplicate_jsonl_keys_fail_closed(self) -> None:
        lines = self.raw.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1][:-1] + ',"elapsed_ns_total":1}'
        self.raw.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(performance_gate.GateError, "duplicate JSON key"):
            performance_gate.parse_raw(self.raw)

    def test_raw_hash_and_analysis_share_one_snapshot(self) -> None:
        snapshot, metadata, grouped = performance_gate.parse_raw_snapshot(self.raw)
        expected = hashlib.sha256(self.raw.read_bytes()).hexdigest()
        self.raw.write_text('{"replaced":true}\n', encoding="utf-8")
        self.assertEqual(snapshot.sha256, expected)
        analysis = performance_gate.analyse(metadata, grouped, self.budget)
        self.assertIn("encapsulate", analysis)

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
        self.budget["operations"]["combine"]["max_block_median_p95_delta_ns_upper_95"] = True
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

    def test_toolchain_policy_ignores_path_injected_executable_before_running(self) -> None:
        fake_cargo = self.root / "cargo"
        fake_rustc = self.root / "rustc"
        for path in (fake_cargo, fake_rustc):
            path.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            path.chmod(0o700)
        account_home = self.root / "account"
        cargo, rustc, policy, command_output = self.synthetic_rustup_toolchain(
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
                performance_gate,
                "run_line",
                side_effect=command_output,
            ),
        ):
            _identity, selected_cargo, selected_rustc = performance_gate.verified_toolchain(
                self.root, self.budget
            )
        which.assert_not_called()
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)

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
        cargo, rustc, policy, command_output = self.synthetic_rustup_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))

        with (
            mock.patch.object(performance_gate.shutil, "which", return_value=None),
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            mock.patch.object(performance_gate, "run_line", side_effect=command_output),
        ):
            identity, selected_cargo, selected_rustc = performance_gate.verified_toolchain(
                self.root, self.budget
            )
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)
        self.assertEqual(identity["target"], "aarch64-test-target")

    def test_toolchain_policy_ignores_identical_unselected_rustup_alias(self) -> None:
        account_home = self.root / "account"
        toolchains = account_home / ".rustup" / "toolchains"
        cargo, rustc, policy, command_output = self.synthetic_rustup_toolchain(
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
            mock.patch.object(performance_gate, "run_line", side_effect=command_output),
        ):
            identity, selected_cargo, selected_rustc = performance_gate.verified_toolchain(
                self.root, self.budget
            )
        self.assertEqual(selected_cargo, cargo)
        self.assertEqual(selected_rustc, rustc)
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
        cargo, _rustc, policy, _command_output = self.synthetic_rustup_toolchain(
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
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance cargo executable is missing or unsafe",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_rejects_hash_mismatch(self) -> None:
        account_home = self.root / "account"
        cargo, _rustc, policy, _command_output = self.synthetic_rustup_toolchain(
            account_home
        )
        cargo.write_bytes(b"changed cargo")
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
            self.assertRaisesRegex(
                performance_gate.GateError,
                "pinned performance cargo executable differs from toolchain policy",
            ),
        ):
            performance_gate.verified_toolchain(self.root, self.budget)

    def test_toolchain_policy_reports_candidate_disappearance(self) -> None:
        account_home = self.root / "account"
        _cargo, _rustc, policy, _command_output = self.synthetic_rustup_toolchain(
            account_home
        )
        self.budget["toolchain"] = policy
        account = types.SimpleNamespace(pw_dir=str(account_home))
        with (
            mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
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
        cargo, rustc, policy, command_output = self.synthetic_rustup_toolchain(
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

        def wrong_target(
            args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
        ) -> str:
            if args == [str(rustc), "-vV"]:
                return "host: wrong-target"
            return command_output(args, cwd, environment=environment)

        cases = (
            (wrong_cargo_version, "cargo version differs from performance policy"),
            (wrong_rustc_version, "rustc version differs from performance policy"),
            (wrong_target, "rustc target differs from performance policy"),
        )
        for output, message in cases:
            with (
                self.subTest(message=message),
                mock.patch.object(performance_gate.pwd, "getpwuid", return_value=account),
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
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(target))
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(
            environment["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"],
            "/usr/bin/clang",
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
                "aarch64-apple-darwin",
                target,
                private,
            )

    def test_collection_resource_limits_fail_closed(self) -> None:
        parse_samples = performance_gate.bounded_positive_int(
            performance_gate.MAX_COLLECTION_SAMPLES, "samples"
        )
        parse_warmup = performance_gate.bounded_positive_int(
            performance_gate.MAX_COLLECTION_WARMUP_MS, "warmup-ms"
        )
        self.assertEqual(
            parse_samples(str(performance_gate.MAX_COLLECTION_SAMPLES)),
            performance_gate.MAX_COLLECTION_SAMPLES,
        )
        self.assertEqual(
            parse_warmup(str(performance_gate.MAX_COLLECTION_WARMUP_MS)),
            performance_gate.MAX_COLLECTION_WARMUP_MS,
        )
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "must not exceed"):
            parse_samples(str(performance_gate.MAX_COLLECTION_SAMPLES + 1))
        with self.assertRaisesRegex(argparse.ArgumentTypeError, "must not exceed"):
            parse_warmup(str(performance_gate.MAX_COLLECTION_WARMUP_MS + 1))


if __name__ == "__main__":
    unittest.main()
