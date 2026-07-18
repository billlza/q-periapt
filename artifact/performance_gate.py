#!/usr/bin/env python3
"""Collect and verify paired, matched-backend profile performance evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict
from typing import Any, Callable

try:
    import pwd
except ImportError:
    pwd = None

from claim_ledger import LedgerError, canonical_tree_digest, repository_paths
from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    JsonObjectSnapshot,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    git_commit as provenance_git_commit,
    require_commit_or_evidence_successor,
    source_tree_dirty as provenance_source_tree_dirty,
)
from proof_manifest import (
    ProofManifestError,
    load_results_manifest_snapshot,
    select_bound_json_snapshot,
)


PROOF_SCHEMA_VERSION = 4
HARNESS_SCHEMA_VERSION = 2
BUDGET_SCHEMA_VERSION = 4
OPERATIONS = ("combine", "encapsulate", "decapsulate")
PROFILES = ("ContextBound", "CompatXWing")
EXPECTED_ITERATIONS_PER_SAMPLE = {
    "combine": 256,
    "encapsulate": 1,
    "decapsulate": 2,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
MAX_EXACT_ELAPSED_NS_TOTAL = 1 << 53
PRODUCTION_BUDGET_RELATIVE = pathlib.PurePosixPath("artifact/performance-budgets.json")
MAX_PERFORMANCE_PROOF_BYTES = 4 * 1024 * 1024
MAX_PERFORMANCE_BUDGET_BYTES = 1024 * 1024
MAX_PERFORMANCE_RAW_BYTES = 128 * 1024 * 1024
# The harness emits six JSONL sample records for each requested sample.  This
# cap keeps the producer below the independent 128 MiB raw-evidence bound.
MAX_COLLECTION_SAMPLES = 100_000
MAX_COLLECTION_WARMUP_MS = 60_000


class GateError(ValueError):
    """A fail-closed performance evidence validation error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def require_verification_policy(
    max_age_seconds: int,
    *,
    allow_dirty: bool,
    allow_uncontrolled: bool,
) -> None:
    if allow_dirty:
        return
    require(
        max_age_seconds == DEFAULT_MAX_AGE_SECONDS,
        "release verification fixes performance proof freshness to 86400 seconds",
    )
    require(
        not allow_uncontrolled,
        "uncontrolled performance verification is diagnostic and requires --allow-dirty",
    )


def finite_number(value: Any, label: str) -> float:
    require(type(value) in (int, float), f"{label} must be a number")
    converted = float(value)
    require(math.isfinite(converted), f"{label} must be finite")
    return converted


def production_budget_path(root: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(os.path.abspath(root.joinpath(*PRODUCTION_BUDGET_RELATIVE.parts)))


def verified_production_budget_snapshot(
    root: pathlib.Path,
    artifacts: dict[str, Any],
) -> JsonObjectSnapshot:
    """Load the fixed release budget; evidence cannot select its own policy."""

    require(
        artifacts.get("budget_path") == PRODUCTION_BUDGET_RELATIVE.as_posix(),
        "performance proof must use artifact/performance-budgets.json",
    )
    expected = artifacts.get("budget_sha256")
    require(
        isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
        "proof budget_sha256 is malformed",
    )
    budget_path = production_budget_path(root)
    try:
        snapshot = load_json_object_snapshot(
            budget_path,
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="production performance budget",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    require(
        snapshot.file.sha256 == expected,
        f"performance artifact changed: {budget_path}",
    )
    return snapshot


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GateError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def run_line(
    args: list[str], cwd: pathlib.Path, *, environment: dict[str, str] | None = None
) -> str:
    try:
        return subprocess.check_output(
            args,
            cwd=cwd,
            env=environment,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"cannot run {' '.join(args)}: {exc}") from exc


def git_commit(root: pathlib.Path) -> str:
    try:
        return provenance_git_commit(root)
    except GitProvenanceError as exc:
        raise GateError(f"cannot inspect git commit: {exc}") from exc


def source_tree_dirty(root: pathlib.Path) -> bool:
    try:
        return provenance_source_tree_dirty(root)
    except GitProvenanceError as exc:
        raise GateError(f"cannot inspect git worktree: {exc}") from exc


def source_tree_digest(root: pathlib.Path) -> str:
    try:
        return canonical_tree_digest(root, repository_paths(root))
    except (LedgerError, OSError, subprocess.CalledProcessError, UnicodeDecodeError) as exc:
        raise GateError(f"cannot compute canonical source-input digest: {exc}") from exc


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise GateError(f"{label} must be under {base}: {path}") from exc
    require(resolved != base.resolve(), f"{label} must not be the target root")
    return resolved


def relative_to_root(path: pathlib.Path, root: pathlib.Path, label: str) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise GateError(f"{label} must be under repository root: {path}") from exc


def require_distinct_paths(paths: dict[str, pathlib.Path]) -> None:
    resolved: dict[pathlib.Path, str] = {}
    for label, path in paths.items():
        canonical = path.resolve()
        previous = resolved.get(canonical)
        require(previous is None, f"{label} must be distinct from {previous}: {canonical}")
        resolved[canonical] = label


def percentile(values: list[float], percent: int) -> float:
    require(bool(values), "cannot take percentile of an empty sample")
    require(0 < percent <= 100, f"invalid percentile: {percent}")
    ordered = sorted(values)
    index = max(0, math.ceil(percent * len(ordered) / 100) - 1)
    return ordered[index]


def percentile_tail_observation_count(sample_count: int, percent: int) -> int:
    """Return the nearest-rank tail count supporting a percentile estimate."""

    require(type(sample_count) is int and sample_count > 0, "percentile sample count must be positive")
    require(type(percent) is int and 0 < percent <= 100, f"invalid percentile: {percent}")
    rank = math.ceil(percent * sample_count / 100)
    return sample_count - rank + 1


def coefficient_of_variation(values: list[float]) -> float:
    require(len(values) >= 2, "at least two blocks are required for environment stability")
    mean = statistics.fmean(values)
    require(mean > 0, "block mean must be positive")
    return statistics.pstdev(values) / mean


def moving_block_bootstrap_median_upper(
    values: list[float],
    *,
    block_span: int,
    resamples: int = 5000,
) -> float:
    """Return a deterministic one-sided upper bound for the same block-median estimand."""

    require(len(values) >= 2, "at least two estimate blocks are required for bootstrap")
    require(type(block_span) is int and block_span > 0, "bootstrap block span must be positive")
    require(block_span <= len(values), "bootstrap block span exceeds the estimate-block count")
    rng = random.Random(0x5150455249415054)
    size = len(values)
    blocks_per_resample = math.ceil(size / block_span)
    medians: list[float] = []
    for _ in range(resamples):
        sample: list[float] = []
        for _block in range(blocks_per_resample):
            start = rng.randrange(size)
            sample.extend(values[(start + offset) % size] for offset in range(block_span))
        medians.append(percentile(sample[:size], 50))
    point = percentile(values, 50)
    return max(point, percentile(medians, 95))


def _strict_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    extra = set(value) - expected
    missing = expected - set(value)
    require(not extra, f"{label} has unknown fields: {sorted(extra)}")
    require(not missing, f"{label} is missing fields: {sorted(missing)}")


def positive_operation_map(value: Any, label: str) -> dict[str, int]:
    require(isinstance(value, dict), f"{label} must be an object")
    _strict_keys(value, set(OPERATIONS), label)
    for operation in OPERATIONS:
        require(
            type(value[operation]) is int and value[operation] > 0,
            f"{label}/{operation} must be a positive integer",
        )
    return value


def parse_raw_bytes(
    data: bytes,
) -> tuple[dict[str, Any], dict[tuple[str, str], list[dict[str, Any]]]]:
    lines = data.splitlines()
    require(bool(lines), "raw performance data is empty")

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        require(bool(line), f"blank JSONL record at line {line_number}")
        try:
            value = parse_strict_json_bytes(
                line,
                label=f"performance JSONL record {line_number}",
            )
        except EvidenceIOError as exc:
            raise GateError(str(exc)) from exc
        require(isinstance(value, dict), f"JSONL record {line_number} is not an object")
        records.append(value)

    metadata = records[0]
    metadata_fields = {
        "schema_version",
        "record_type",
        "backend",
        "schedule",
        "corpus_size",
        "samples_per_profile_operation",
        "iterations_per_sample",
        "warmup_ms",
        "suite_id_hex",
        "policy_version",
        "application_context_hex",
    }
    _strict_keys(metadata, metadata_fields, "metadata record")
    require(type(metadata.get("schema_version")) is int, "harness schema must be an integer")
    require(metadata.get("schema_version") == HARNESS_SCHEMA_VERSION, "harness schema mismatch")
    require(metadata.get("record_type") == "metadata", "first JSONL record must be metadata")
    require(isinstance(metadata.get("backend"), str) and bool(metadata["backend"]), "invalid metadata backend")
    require(metadata.get("schedule") == "ABBA/BAAB", "unsupported metadata schedule")
    for field in ("suite_id_hex", "application_context_hex"):
        value = metadata.get(field)
        require(isinstance(value, str) and HEX_RE.fullmatch(value) is not None, f"invalid metadata {field}")
    require(type(metadata.get("policy_version")) is int and metadata["policy_version"] > 0, "invalid policy version")
    require(type(metadata.get("warmup_ms")) is int and metadata["warmup_ms"] > 0, "invalid warmup duration")
    iterations_per_sample = positive_operation_map(
        metadata.get("iterations_per_sample"),
        "metadata iterations_per_sample",
    )
    require(
        iterations_per_sample == EXPECTED_ITERATIONS_PER_SAMPLE,
        "metadata iterations_per_sample does not match the harness contract",
    )

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    sample_fields = {
        "schema_version",
        "record_type",
        "operation",
        "profile",
        "pair_id",
        "schedule_index",
        "corpus_index",
        "elapsed_ns_total",
    }
    seen: set[tuple[str, int, str]] = set()
    for index, record in enumerate(records[1:], start=2):
        _strict_keys(record, sample_fields, f"sample record {index}")
        require(type(record.get("schema_version")) is int, f"sample schema must be an integer at line {index}")
        require(record.get("schema_version") == HARNESS_SCHEMA_VERSION, f"sample schema mismatch at line {index}")
        require(record.get("record_type") == "sample", f"non-sample record at line {index}")
        operation = record.get("operation")
        profile_name = record.get("profile")
        require(operation in OPERATIONS, f"unknown operation at line {index}: {operation}")
        require(profile_name in PROFILES, f"unknown profile at line {index}: {profile_name}")
        for field in ("pair_id", "schedule_index", "corpus_index", "elapsed_ns_total"):
            require(type(record.get(field)) is int, f"{field} must be an integer at line {index}")
            require(record[field] >= 0, f"{field} must be non-negative at line {index}")
        require(record["elapsed_ns_total"] > 0, f"elapsed_ns_total must be positive at line {index}")
        require(
            record["elapsed_ns_total"] <= MAX_EXACT_ELAPSED_NS_TOTAL,
            f"elapsed_ns_total exceeds exact analysis range at line {index}",
        )
        key = (operation, record["pair_id"], profile_name)
        require(key not in seen, f"duplicate paired sample: {key}")
        seen.add(key)
        grouped[(operation, profile_name)].append(record)

    expected_samples = metadata.get("samples_per_profile_operation")
    corpus_size = metadata.get("corpus_size")
    require(type(expected_samples) is int and expected_samples > 0, "invalid metadata sample count")
    require(expected_samples % 2 == 0, "metadata sample count must be even for ABBA/BAAB")
    require(type(corpus_size) is int and corpus_size > 0, "invalid metadata corpus size")
    for operation in OPERATIONS:
        by_pair: dict[int, dict[str, dict[str, Any]]] = defaultdict(dict)
        schedule_records: list[dict[str, Any]] = []
        for profile_name in PROFILES:
            samples = grouped[(operation, profile_name)]
            require(
                len(samples) == expected_samples,
                f"{operation}/{profile_name} has {len(samples)} samples, expected {expected_samples}",
            )
            for record in samples:
                by_pair[record["pair_id"]][profile_name] = record
                schedule_records.append(record)
        require(set(by_pair) == set(range(expected_samples)), f"{operation} pair ids are not contiguous")
        for pair_id, pair in by_pair.items():
            require(set(pair) == set(PROFILES), f"{operation} pair {pair_id} is incomplete")
            for record in pair.values():
                require(
                    record["corpus_index"] == pair_id % corpus_size,
                    f"{operation} pair {pair_id} has the wrong corpus index",
                )
        ordered = sorted(schedule_records, key=lambda record: record["schedule_index"])
        require(
            [record["schedule_index"] for record in ordered] == list(range(expected_samples * 2)),
            f"{operation} schedule indexes are not contiguous",
        )
        for cycle in range(expected_samples // 2):
            actual_order = [
                (record["profile"], record["pair_id"])
                for record in ordered[cycle * 4 : cycle * 4 + 4]
            ]
            first_pair = cycle * 2
            expected_order = (
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
            require(actual_order == expected_order, f"{operation} schedule cycle {cycle} is not ABBA/BAAB")

    return metadata, grouped


def parse_raw_snapshot(
    path: pathlib.Path,
) -> tuple[FileSnapshot, dict[str, Any], dict[tuple[str, str], list[dict[str, Any]]]]:
    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=MAX_PERFORMANCE_RAW_BYTES,
            label="raw performance data",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    metadata, grouped = parse_raw_bytes(snapshot.data)
    return snapshot, metadata, grouped


def parse_raw(path: pathlib.Path) -> tuple[dict[str, Any], dict[tuple[str, str], list[dict[str, Any]]]]:
    _snapshot, metadata, grouped = parse_raw_snapshot(path)
    return metadata, grouped


def validate_statistical_block_size(
    *,
    samples: int,
    corpus_size: int,
    block_size: Any,
    label: str,
) -> int:
    require(type(block_size) is int and block_size > 1, f"invalid {label}")
    require(block_size % 2 == 0, f"{label} must contain complete ABBA two-pair cycles")
    require(
        block_size % corpus_size == 0,
        f"{label} must be a multiple of corpus size {corpus_size}",
    )
    require(samples % block_size == 0, f"sample count {samples} is not divisible by {label} {block_size}")
    require(samples // block_size >= 2, f"performance budget requires at least two {label} blocks")
    return block_size


def validate_budget(metadata: dict[str, Any], budget: dict[str, Any]) -> None:
    expected_fields = {
        "schema_version",
        "harness_schema_version",
        "backend",
        "schedule",
        "corpus_size",
        "iterations_per_sample",
        "min_samples_per_profile_operation",
        "warmup_ms",
        "pair_block_size",
        "regression_guard_pair_block_size",
        "min_p99_tail_observations_per_pair_block",
        "stability_block_sizes",
        "bootstrap_estimate_block_span",
        "max_block_median_cv",
        "operations",
        "toolchain",
    }
    _strict_keys(budget, expected_fields, "performance budget")
    require(type(budget.get("schema_version")) is int, "performance budget schema must be an integer")
    require(
        budget.get("schema_version") == BUDGET_SCHEMA_VERSION,
        "performance budget schema mismatch",
    )
    require(type(budget.get("harness_schema_version")) is int, "budget harness schema must be an integer")
    require(budget.get("harness_schema_version") == HARNESS_SCHEMA_VERSION, "budget harness schema mismatch")
    validate_toolchain_policy(budget.get("toolchain"))
    for field in ("backend", "schedule", "corpus_size"):
        require(metadata.get(field) == budget.get(field), f"metadata/budget mismatch for {field}")
    budget_iterations = positive_operation_map(
        budget.get("iterations_per_sample"),
        "budget iterations_per_sample",
    )
    require(
        budget_iterations == EXPECTED_ITERATIONS_PER_SAMPLE,
        "budget iterations_per_sample does not match the harness contract",
    )
    require(
        metadata.get("iterations_per_sample") == budget_iterations,
        "metadata/budget mismatch for iterations_per_sample",
    )
    samples = metadata.get("samples_per_profile_operation")
    minimum = budget.get("min_samples_per_profile_operation")
    require(type(minimum) is int and minimum > 0, "invalid minimum sample budget")
    require(type(samples) is int and samples >= minimum, f"sample count {samples} is below budget {minimum}")
    warmup = budget.get("warmup_ms")
    require(type(warmup) is int and warmup > 0, "invalid warmup budget")
    require(metadata.get("warmup_ms") == warmup, "metadata/budget mismatch for warmup_ms")
    corpus_size = metadata["corpus_size"]
    pair_block_size = validate_statistical_block_size(
        samples=samples,
        corpus_size=corpus_size,
        block_size=budget.get("pair_block_size"),
        label="pair block size",
    )
    regression_guard_pair_block_size = validate_statistical_block_size(
        samples=samples,
        corpus_size=corpus_size,
        block_size=budget.get("regression_guard_pair_block_size"),
        label="regression-guard pair block size",
    )
    require(
        regression_guard_pair_block_size < pair_block_size,
        "regression-guard pair block size must be smaller than the primary pair block size",
    )
    minimum_p99_tail = budget.get("min_p99_tail_observations_per_pair_block")
    require(
        type(minimum_p99_tail) is int and minimum_p99_tail > 0,
        "invalid minimum p99 tail-observation budget",
    )
    p99_tail_observations = percentile_tail_observation_count(pair_block_size, 99)
    require(
        p99_tail_observations >= minimum_p99_tail,
        "pair block size provides too few p99 tail observations: "
        f"{p99_tail_observations} < {minimum_p99_tail}",
    )
    stability_block_sizes = positive_operation_map(
        budget.get("stability_block_sizes"),
        "stability_block_sizes",
    )
    for operation, stability_block_size in stability_block_sizes.items():
        validate_statistical_block_size(
            samples=samples,
            corpus_size=corpus_size,
            block_size=stability_block_size,
            label=f"{operation} stability block size",
        )
    bootstrap_span = budget.get("bootstrap_estimate_block_span")
    require(type(bootstrap_span) is int and bootstrap_span > 0, "invalid bootstrap estimate-block span")
    require(
        bootstrap_span <= samples // pair_block_size,
        "bootstrap estimate-block span exceeds the paired estimate-block count",
    )
    operations = budget.get("operations")
    require(isinstance(operations, dict) and set(operations) == set(OPERATIONS), "budget operation inventory mismatch")
    maximum_cv = finite_number(budget.get("max_block_median_cv"), "maximum block-median CV")
    require(0 < maximum_cv <= 1, "maximum block-median CV must be in (0, 1]")


def validate_toolchain_policy(value: Any) -> dict[str, str]:
    require(isinstance(value, dict), "performance budget lacks toolchain policy")
    expected = {
        "cargo_sha256",
        "cargo_version",
        "rustc_sha256",
        "rustc_version",
        "target",
    }
    _strict_keys(value, expected, "performance toolchain policy")
    for field in expected:
        item = value.get(field)
        require(isinstance(item, str) and bool(item), f"toolchain policy {field} is missing")
    for field in ("cargo_sha256", "rustc_sha256"):
        require(SHA256_RE.fullmatch(value[field]) is not None, f"toolchain policy {field} is malformed")
    require("/" not in value["target"] and "\\" not in value["target"], "toolchain target is malformed")
    return value


def analyse(
    metadata: dict[str, Any],
    grouped: dict[tuple[str, str], list[dict[str, Any]]],
    budget: dict[str, Any],
) -> dict[str, Any]:
    validate_budget(metadata, budget)
    pair_block_size = budget["pair_block_size"]
    regression_guard_pair_block_size = budget["regression_guard_pair_block_size"]
    stability_block_sizes = budget["stability_block_sizes"]
    bootstrap_span = budget["bootstrap_estimate_block_span"]
    max_cv = finite_number(budget["max_block_median_cv"], "maximum block-median CV")
    iterations_per_sample = metadata["iterations_per_sample"]
    result: dict[str, Any] = {}

    for operation in OPERATIONS:
        by_profile_pair: dict[str, dict[int, float]] = {}
        profile_summary: dict[str, Any] = {}
        max_observed_cv = 0.0
        for profile_name in PROFILES:
            iterations = iterations_per_sample[operation]
            pair_map = {
                int(record["pair_id"]): float(record["elapsed_ns_total"]) / iterations
                for record in grouped[(operation, profile_name)]
            }
            by_profile_pair[profile_name] = pair_map
            sample_count = int(metadata["samples_per_profile_operation"])
            values = [pair_map[pair_id] for pair_id in range(sample_count)]
            stability_block_size = stability_block_sizes[operation]
            block_medians = [
                percentile(values[offset : offset + stability_block_size], 50)
                for offset in range(0, len(values), stability_block_size)
            ]
            cv = coefficient_of_variation(block_medians)
            max_observed_cv = max(max_observed_cv, cv)
            profile_summary[profile_name] = {
                "p50_ns": percentile(values, 50),
                "p95_ns": percentile(values, 95),
                "p99_ns": percentile(values, 99),
                "block_median_cv": cv,
            }
        require(
            max_observed_cv <= max_cv,
            f"INVALID_ENV {operation} block-median CV {max_observed_cv:.6f} exceeds {max_cv:.6f}",
        )

        sample_count = int(metadata["samples_per_profile_operation"])
        global_descriptive = {
            "p50_ratio": profile_summary["ContextBound"]["p50_ns"] / profile_summary["CompatXWing"]["p50_ns"],
            "p95_ratio": profile_summary["ContextBound"]["p95_ns"] / profile_summary["CompatXWing"]["p95_ns"],
            "p99_ratio": profile_summary["ContextBound"]["p99_ns"] / profile_summary["CompatXWing"]["p99_ns"],
            "p95_delta_ns": profile_summary["ContextBound"]["p95_ns"] - profile_summary["CompatXWing"]["p95_ns"],
        }
        paired = paired_block_metrics(
            operation,
            by_profile_pair,
            sample_count=sample_count,
            pair_block_size=pair_block_size,
            bootstrap_span=bootstrap_span,
        )
        regression_guard_paired = paired_block_metrics(
            operation,
            by_profile_pair,
            sample_count=sample_count,
            pair_block_size=regression_guard_pair_block_size,
            bootstrap_span=bootstrap_span,
        )

        operation_budget = budget["operations"][operation]
        require(isinstance(operation_budget, dict), f"budget for {operation} must be an object")
        ratio_and_delta_fields = {
            "max_block_median_p50_ratio_upper_95",
            "max_block_median_p95_ratio_upper_95",
            "max_block_median_p99_ratio_upper_95",
            "max_block_median_p95_delta_ns_upper_95",
        }
        expected_budget_fields = (
            {"max_block_median_p95_delta_ns_upper_95"} if operation == "combine" else ratio_and_delta_fields
        )
        require(
            set(operation_budget) == expected_budget_fields,
            f"budget for {operation} metric inventory mismatch: expected {sorted(expected_budget_fields)}",
        )
        enforce_operation_budget(operation, operation_budget, paired, "primary")
        enforce_operation_budget(
            operation,
            operation_budget,
            regression_guard_paired,
            "regression_guard",
        )
        result[operation] = {
            "profiles": profile_summary,
            "global_descriptive": global_descriptive,
            "paired": paired,
            "regression_guard_paired": regression_guard_paired,
            "max_block_median_cv": max_observed_cv,
            "pair_block_size": pair_block_size,
            "regression_guard_pair_block_size": regression_guard_pair_block_size,
            "p99_tail_observations_per_pair_block": percentile_tail_observation_count(
                pair_block_size, 99
            ),
            "stability_block_size": stability_block_sizes[operation],
            "bootstrap_estimate_block_span": bootstrap_span,
        }

    return result


def paired_block_metrics(
    operation: str,
    by_profile_pair: dict[str, dict[int, float]],
    *,
    sample_count: int,
    pair_block_size: int,
    bootstrap_span: int,
) -> dict[str, float]:
    """Compute one block-scale paired estimand from the same ordered samples."""

    block_ratios: dict[int, list[float]] = {50: [], 95: [], 99: []}
    block_p95_deltas: list[float] = []
    for offset in range(0, sample_count, pair_block_size):
        pair_ids = range(offset, offset + pair_block_size)
        bound = [by_profile_pair["ContextBound"][pair_id] for pair_id in pair_ids]
        compat = [by_profile_pair["CompatXWing"][pair_id] for pair_id in pair_ids]
        for percent in (50, 95, 99):
            denominator = percentile(compat, percent)
            require(
                denominator > 0,
                f"{operation} CompatXWing p{percent} is not positive",
            )
            block_ratios[percent].append(
                percentile(bound, percent) / denominator
            )
        block_p95_deltas.append(
            percentile(bound, 95) - percentile(compat, 95)
        )

    paired = {
        "block_median_p50_ratio": percentile(block_ratios[50], 50),
        "block_median_p50_ratio_upper_95": moving_block_bootstrap_median_upper(
            block_ratios[50], block_span=bootstrap_span
        ),
        "block_median_p95_ratio": percentile(block_ratios[95], 50),
        "block_median_p95_ratio_upper_95": moving_block_bootstrap_median_upper(
            block_ratios[95], block_span=bootstrap_span
        ),
        "block_median_p99_ratio": percentile(block_ratios[99], 50),
        "block_median_p99_ratio_upper_95": moving_block_bootstrap_median_upper(
            block_ratios[99], block_span=bootstrap_span
        ),
        "block_median_p95_delta_ns": percentile(block_p95_deltas, 50),
        "block_median_p95_delta_ns_upper_95": moving_block_bootstrap_median_upper(
            block_p95_deltas, block_span=bootstrap_span
        ),
    }
    for metric in ("p50_ratio", "p95_ratio", "p99_ratio", "p95_delta_ns"):
        point_name = f"block_median_{metric}"
        upper_name = f"{point_name}_upper_95"
        require(
            paired[upper_name] >= paired[point_name],
            f"bootstrap upper bound is below {point_name}",
        )
    return paired


def enforce_operation_budget(
    operation: str,
    operation_budget: dict[str, Any],
    paired: dict[str, float],
    estimator_label: str,
) -> None:
    """Apply the same published limits to one separately recomputed block scale."""

    for metric, limit in operation_budget.items():
        actual_name = metric.removeprefix("max_")
        actual = paired[actual_name]
        numeric_limit = finite_number(limit, f"budget {operation}/{metric}")
        require(numeric_limit > 0, f"budget {operation}/{metric} must be positive")
        require(
            actual <= numeric_limit,
            "BUDGET_FAIL "
            f"{operation} {estimator_label}.{actual_name}={actual:.6f} "
            f"exceeds {numeric_limit:.6f}",
        )


def required_command_output(args: list[str], label: str) -> str:
    try:
        return subprocess.check_output(
            args,
            text=True,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"},
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"cannot collect {label}: {exc}") from exc


def collect_environment() -> dict[str, Any]:
    system = platform.system()
    cpu = (
        required_command_output(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"],
            "Darwin CPU identity",
        )
        if system == "Darwin"
        else platform.processor()
    )
    thermal = "unsupported"
    ac_power: bool | None = None
    controlled = False
    if system == "Darwin":
        thermal_text = required_command_output(
            ["/usr/bin/pmset", "-g", "therm"], "Darwin thermal state"
        )
        power_text = required_command_output(
            ["/usr/bin/pmset", "-g", "batt"], "Darwin power state"
        )
        thermal = (
            "nominal"
            if "No thermal warning level has been recorded" in thermal_text
            and "No performance warning level has been recorded" in thermal_text
            else "warning_or_unknown"
        )
        ac_power = "AC Power" in power_text
        controlled = thermal == "nominal" and ac_power is True
    return {
        "system": system,
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu": cpu,
        "thermal": thermal,
        "ac_power": ac_power,
        "controlled": controlled,
    }


def host_target(
    root: pathlib.Path,
    rustc: str = "rustc",
    *,
    environment: dict[str, str] | None = None,
) -> str:
    rustc_metadata = run_line([rustc, "-vV"], root, environment=environment)
    for line in rustc_metadata.splitlines():
        if line.startswith("host: "):
            target = line.removeprefix("host: ").strip()
            require(bool(target) and "/" not in target and "\\" not in target, f"malformed rustc host: {target}")
            return target
    raise GateError("rustc -vV did not report a host target")


def binary_path(target_dir: pathlib.Path, target: str) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir / target / "release" / "examples" / f"paired_profile_perf{suffix}"


def verified_toolchain(
    root: pathlib.Path, budget: dict[str, Any]
) -> tuple[dict[str, str], pathlib.Path, pathlib.Path]:
    policy = validate_toolchain_policy(budget.get("toolchain"))
    account_home = account_home_directory()
    candidate_directories: set[pathlib.Path] = set()
    for name in ("cargo", "rustc"):
        selected = shutil.which(name)
        if selected is not None:
            candidate_directories.add(pathlib.Path(selected).absolute().parent)
    rustup_toolchains = account_home / ".rustup" / "toolchains"
    if rustup_toolchains.is_dir():
        try:
            toolchain_directories = list(rustup_toolchains.iterdir())
        except OSError as exc:
            raise GateError(f"cannot enumerate Rust toolchains: {exc}") from exc
        candidate_directories.update(
            path / "bin"
            for path in toolchain_directories
            if path.is_dir() and not path.is_symlink()
        )

    matches: list[dict[str, pathlib.Path]] = []
    for directory in sorted(candidate_directories):
        pair: dict[str, pathlib.Path] = {}
        for name in ("cargo", "rustc"):
            candidate = directory / name
            if (
                not candidate.is_file()
                or candidate.is_symlink()
                or not os.access(candidate, os.X_OK)
            ):
                break
            resolved = candidate.resolve(strict=True)
            if sha256_file(resolved) != policy[f"{name}_sha256"]:
                break
            pair[name] = resolved
        if set(pair) == {"cargo", "rustc"}:
            matches.append(pair)

    require(
        len(matches) == 1,
        "expected exactly one same-directory cargo/rustc pair matching the "
        f"performance toolchain policy, found {len(matches)}",
    )
    resolved = matches[0]
    command_environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
    }
    cargo_version = run_line(
        [str(resolved["cargo"]), "--version"], root, environment=command_environment
    )
    rustc_version = run_line(
        [str(resolved["rustc"]), "--version"], root, environment=command_environment
    )
    target = host_target(
        root, str(resolved["rustc"]), environment=command_environment
    )
    identity = {
        "cargo": cargo_version,
        "cargo_path": str(resolved["cargo"]),
        "cargo_sha256": sha256_file(resolved["cargo"]),
        "rustc": rustc_version,
        "rustc_path": str(resolved["rustc"]),
        "rustc_sha256": sha256_file(resolved["rustc"]),
        "target": target,
    }
    require(cargo_version == policy["cargo_version"], "cargo version differs from performance policy")
    require(rustc_version == policy["rustc_version"], "rustc version differs from performance policy")
    require(target == policy["target"], "rustc target differs from performance policy")
    return identity, resolved["cargo"], resolved["rustc"]


def require_toolchain_unchanged(
    toolchain: dict[str, str], cargo: pathlib.Path, rustc: pathlib.Path
) -> None:
    """Detect ordinary tool replacement across a collection or verification window."""

    for name, path in (("cargo", cargo), ("rustc", rustc)):
        require(path.is_file() and not path.is_symlink(), f"{name} executable became unsafe")
        require(
            sha256_file(path) == toolchain[f"{name}_sha256"],
            f"{name} executable changed during performance evidence processing",
        )


def account_home_directory() -> pathlib.Path:
    require(pwd is not None, "performance collection requires a POSIX account database")
    try:
        return pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError) as exc:
        raise GateError(f"cannot resolve the performance account home: {exc}") from exc


def build_harness(
    root: pathlib.Path,
    target: str,
    cargo: pathlib.Path,
    target_dir: pathlib.Path,
    environment: dict[str, str],
) -> tuple[pathlib.Path, str]:
    command = [
        str(cargo),
        "build",
        "--release",
        "--locked",
        "--target",
        target,
        "-p",
        "q-periapt-backends",
        "--example",
        "paired_profile_perf",
    ]
    try:
        subprocess.run(command, cwd=root, env=environment, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"performance harness build failed: {exc}") from exc
    executable = binary_path(target_dir, target)
    require(executable.is_file(), f"performance harness binary is missing: {executable}")
    require(not executable.is_symlink(), f"performance harness binary must not be a symlink: {executable}")
    require_under(executable, target_dir, "performance binary")
    return executable.resolve(), sha256_file(executable)


def publish_performance_binary(
    root: pathlib.Path, target: str, executable: pathlib.Path, digest: str
) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    destination = (
        root
        / "target"
        / "performance"
        / "binaries"
        / target
        / f"paired_profile_perf-{digest}{suffix}"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(not destination.is_symlink() and destination.is_file(), "performance evidence binary is unsafe")
        require(sha256_file(destination) == digest, "performance evidence binary hash collision")
        return destination.resolve()
    try:
        with executable.open("rb") as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        destination.chmod(0o700)
    except OSError as exc:
        raise GateError(f"cannot publish performance evidence binary: {exc}") from exc
    require(sha256_file(destination) == digest, "published performance binary changed during copy")
    return destination.resolve()


def hardened_cargo_environment(
    root: pathlib.Path,
    cargo: pathlib.Path,
    rustc: pathlib.Path,
    target: str,
    target_dir: pathlib.Path,
    private_root: pathlib.Path,
) -> dict[str, str]:
    home = account_home_directory()
    cargo_home = (home / ".cargo").resolve()
    require(cargo_home.is_dir(), f"Cargo home is missing: {cargo_home}")
    configuration_roots = [root.resolve(), *root.resolve().parents, cargo_home]
    checked_configurations: set[pathlib.Path] = set()
    for configuration_root in configuration_roots:
        cargo_config_root = (
            configuration_root
            if configuration_root == cargo_home
            else configuration_root / ".cargo"
        )
        for config_name in ("config", "config.toml"):
            configuration = cargo_config_root / config_name
            if configuration in checked_configurations:
                continue
            checked_configurations.add(configuration)
            require(
                not os.path.lexists(configuration),
                f"performance collection rejects Cargo configuration: {configuration}",
            )
    private_home = private_root / "home"
    private_tmp = private_root / "tmp"
    private_home.mkdir(mode=0o700)
    private_tmp.mkdir(mode=0o700)
    target_linker_key = (
        "CARGO_TARGET_" + re.sub(r"[^A-Za-z0-9]", "_", target).upper() + "_LINKER"
    )
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(private_home),
        "TMPDIR": str(private_tmp),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "RUSTC": str(rustc),
        "CC": "/usr/bin/clang",
        "AR": "/usr/bin/ar",
        target_linker_key: "/usr/bin/clang",
        "LC_ALL": "C",
        "LANG": "C",
    }


def verify_environment(environment: dict[str, Any], allow_uncontrolled: bool) -> None:
    require(isinstance(environment, dict), "performance proof lacks environment metadata")
    _strict_keys(
        environment,
        {"system", "release", "machine", "cpu", "thermal", "ac_power", "controlled"},
        "performance environment",
    )
    for field in ("system", "release", "machine", "cpu", "thermal"):
        require(isinstance(environment.get(field), str) and bool(environment[field]), f"environment {field} is missing")
    require(type(environment.get("ac_power")) is bool or environment.get("ac_power") is None, "invalid AC power state")
    require(isinstance(environment.get("controlled"), bool), "environment controlled flag is missing")
    if environment["controlled"]:
        require(environment["thermal"] == "nominal", "controlled environment must have nominal thermal state")
        require(environment["ac_power"] is True, "controlled environment must use AC power")
    if not allow_uncontrolled:
        require(environment["controlled"] is True, "INVALID_ENV host is not a controlled AC/nominal-thermal environment")


def verify_environment_observations(
    observations: dict[str, Any], allow_uncontrolled: bool
) -> None:
    require(isinstance(observations, dict), "performance proof lacks environment observations")
    labels = {"pre_build", "pre_run", "post_run", "post_analysis"}
    _strict_keys(observations, labels, "performance environment observations")
    baseline: dict[str, Any] | None = None
    for label in ("pre_build", "pre_run", "post_run", "post_analysis"):
        observation = observations.get(label)
        verify_environment(observation, allow_uncontrolled)
        if baseline is None:
            baseline = observation
            continue
        for field in ("system", "release", "machine", "cpu"):
            require(
                observation.get(field) == baseline.get(field),
                f"performance environment changed for {field} at {label}",
            )


def proof_artifact_path(root: pathlib.Path, relative: Any, label: str) -> pathlib.Path:
    require(isinstance(relative, str) and relative, f"proof lacks {label} path")
    pure = pathlib.PurePosixPath(relative)
    require(
        not pure.is_absolute()
        and ".." not in pure.parts
        and pure.as_posix() == relative
        and "\\" not in relative,
        f"proof {label} path is not canonical: {relative}",
    )
    path = pathlib.Path(os.path.abspath(root.joinpath(*pure.parts)))
    require_under(path, root / "target", label)
    return path


def emit_proof(
    root: pathlib.Path,
    raw_path: pathlib.Path,
    proof_path: pathlib.Path,
    metadata: dict[str, Any],
    analysis: dict[str, Any],
    environment_observations: dict[str, Any],
    tree_digest: str,
    executable: pathlib.Path,
    binary_digest: str,
    toolchain: dict[str, str],
    raw_digest: str,
    budget_digest: str,
) -> dict[str, Any]:
    require(executable.is_file(), f"performance harness binary is missing: {executable}")
    require(sha256_file(executable) == binary_digest, "performance binary changed before proof emission")
    payload = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "git_commit": git_commit(root),
        "source_tree_dirty": source_tree_dirty(root),
        "proof_source_tree_sha256": tree_digest,
        "environment": environment_observations,
        "toolchain": toolchain,
        "harness": metadata,
        "artifacts": {
            "raw_path": relative_to_root(raw_path, root, "raw performance data"),
            "raw_sha256": raw_digest,
            "binary_path": relative_to_root(executable, root, "performance binary"),
            "binary_sha256": binary_digest,
            "budget_path": PRODUCTION_BUDGET_RELATIVE.as_posix(),
            "budget_sha256": budget_digest,
        },
        "analysis": analysis,
        "gate": {"passed": True},
    }
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    proof_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def collect(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    require(
        not args.allow_uncontrolled or args.allow_dirty,
        "uncontrolled performance collection is diagnostic and requires --allow-dirty",
    )
    raw_path = require_under(args.raw.resolve(), root / "target", "raw performance data")
    proof_path = require_under(args.proof.resolve(), root / "target", "performance proof")
    require_distinct_paths(
        {
            "raw performance data": raw_path,
            "performance proof": proof_path,
        }
    )
    budget_path = production_budget_path(root)
    require(budget_path.is_file(), f"performance budget is missing: {budget_path}")
    try:
        budget_snapshot = load_json_object_snapshot(
            budget_path,
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="production performance budget",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    if not args.allow_dirty:
        require(not source_tree_dirty(root), "performance release proof requires a clean source tree")
    environment_observations = {"pre_build": collect_environment()}
    verify_environment(
        environment_observations["pre_build"], args.allow_uncontrolled
    )
    before = source_tree_digest(root)
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    if raw_path.exists():
        raw_path.unlink()
    if proof_path.exists():
        proof_path.unlink()
    toolchain, cargo, rustc = verified_toolchain(root, budget_snapshot.value)
    target = toolchain["target"]
    target_parent = root / "target"
    target_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="qperiapt-performance-build-", dir=target_parent
    ) as temporary:
        private_root = pathlib.Path(temporary).resolve()
        target_dir = private_root / "cargo-target"
        target_dir.mkdir(mode=0o700)
        env = hardened_cargo_environment(
            root, cargo, rustc, target, target_dir, private_root
        )
        executable, binary_digest = build_harness(
            root, target, cargo, target_dir, env
        )
        require_distinct_paths(
            {
                "raw performance data": raw_path,
                "performance proof": proof_path,
                "performance binary": executable,
            }
        )
        after_build = source_tree_digest(root)
        require(before == after_build, f"source tree changed during performance build: {before} != {after_build}")
        environment_observations["pre_run"] = collect_environment()
        verify_environment(
            environment_observations["pre_run"], args.allow_uncontrolled
        )
        for field in ("system", "release", "machine", "cpu"):
            require(
                environment_observations["pre_run"].get(field)
                == environment_observations["pre_build"].get(field),
                f"performance environment changed for {field} at pre_run",
            )
        command = [
            str(executable),
            "--samples",
            str(args.samples),
            "--warmup-ms",
            str(args.warmup_ms),
            "--raw-out",
            str(raw_path),
        ]
        try:
            subprocess.run(command, cwd=root, env=env, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise GateError(f"performance harness failed: {exc}") from exc
        environment_observations["post_run"] = collect_environment()
        verify_environment(
            environment_observations["post_run"], args.allow_uncontrolled
        )
        require(sha256_file(executable) == binary_digest, "performance binary changed during collection")
        after_run = source_tree_digest(root)
        require(before == after_run, f"source tree changed during performance collection: {before} != {after_run}")
        raw_snapshot, metadata, grouped = parse_raw_snapshot(raw_path)
        analysis = analyse(metadata, grouped, budget_snapshot.value)
        environment_observations["post_analysis"] = collect_environment()
        verify_environment_observations(
            environment_observations, args.allow_uncontrolled
        )
        require_toolchain_unchanged(toolchain, cargo, rustc)
        before_emit = source_tree_digest(root)
        require(before == before_emit, f"source tree changed before performance proof emission: {before} != {before_emit}")
        evidence_binary = publish_performance_binary(
            root, target, executable, binary_digest
        )
        emit_proof(
            root,
            raw_path,
            proof_path,
            metadata,
            analysis,
            environment_observations,
            before,
            evidence_binary,
            binary_digest,
            toolchain,
            raw_snapshot.sha256,
            budget_snapshot.file.sha256,
        )
    require(
        sha256_file(raw_path) == raw_snapshot.sha256,
        "raw performance data changed during proof emission",
    )
    require(
        source_tree_digest(root) == before,
        "source tree changed during performance proof emission",
    )
    print(f"PAIRED_PROFILE_PERFORMANCE_GATE_PASS proof={proof_path}")


def parse_generated_at(value: Any) -> dt.datetime:
    require(isinstance(value, str) and value, "proof generated_at is missing")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"invalid proof generated_at: {value}") from exc
    require(parsed.tzinfo is not None, "proof generated_at must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def validate_proof_schema(proof: dict[str, Any]) -> None:
    require(type(proof.get("schema_version")) is int, "performance proof schema must be an integer")
    require(proof.get("schema_version") == PROOF_SCHEMA_VERSION, "performance proof schema mismatch")


def cli_performance_proof_snapshot(
    args: argparse.Namespace,
    root: pathlib.Path,
    proof_path: pathlib.Path,
) -> tuple[JsonObjectSnapshot, bool]:
    results_manifest = args.results_manifest
    expected_manifest_sha256 = args.expected_results_manifest_sha256
    bound = bool(results_manifest or expected_manifest_sha256)
    require(
        bool(results_manifest) == bool(expected_manifest_sha256),
        "--results-manifest and --expected-results-manifest-sha256 must be provided together",
    )
    if not bound:
        try:
            return (
                load_json_object_snapshot(
                    proof_path,
                    maximum=MAX_PERFORMANCE_PROOF_BYTES,
                    label="performance proof",
                ),
                False,
            )
        except EvidenceIOError as exc:
            raise GateError(str(exc)) from exc
    manifest_path = pathlib.Path(os.path.abspath(results_manifest))
    require(
        manifest_path == pathlib.Path(os.path.abspath(root / "artifact" / "results.json")),
        "bound verification requires repository artifact/results.json",
    )
    try:
        manifest = load_results_manifest_snapshot(
            manifest_path,
            expected_sha256=expected_manifest_sha256,
        )
        return (
            select_bound_json_snapshot(
                root,
                manifest,
                binding="performance",
                selected_path=proof_path,
                maximum=MAX_PERFORMANCE_PROOF_BYTES,
                label="performance proof",
            ),
            True,
        )
    except ProofManifestError as exc:
        raise GateError(str(exc)) from exc


def verify(args: argparse.Namespace) -> None:
    root = args.root.resolve()
    require_verification_policy(
        args.max_age_seconds,
        allow_dirty=args.allow_dirty,
        allow_uncontrolled=args.allow_uncontrolled,
    )
    selected = args.proof if args.proof.is_absolute() else root / args.proof
    proof_path = pathlib.Path(os.path.abspath(selected))
    require_under(proof_path, root / "target", "performance proof")
    proof_snapshot, manifest_bound = cli_performance_proof_snapshot(
        args,
        root,
        proof_path,
    )
    proof = proof_snapshot.value
    _strict_keys(
        proof,
        {
            "schema_version",
            "generated_at",
            "git_commit",
            "source_tree_dirty",
            "proof_source_tree_sha256",
            "environment",
            "toolchain",
            "harness",
            "artifacts",
            "analysis",
            "gate",
        },
        "performance proof",
    )
    validate_proof_schema(proof)
    generated = parse_generated_at(proof.get("generated_at"))
    age = (dt.datetime.now(dt.timezone.utc) - generated).total_seconds()
    require(age >= 0, "performance proof generated_at is in the future")
    require(age <= args.max_age_seconds, f"performance proof is stale: {int(age)}s")
    commit = proof.get("git_commit")
    require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit) is not None, "proof git commit is malformed")
    try:
        require_commit_or_evidence_successor(root, commit)
    except GitProvenanceError as exc:
        raise GateError(f"performance proof commit provenance failed: {exc}") from exc
    dirty = proof.get("source_tree_dirty")
    require(isinstance(dirty, bool), "performance proof lacks source_tree_dirty")
    if not args.allow_dirty:
        require(dirty is False and not source_tree_dirty(root), "performance release proof requires a clean source tree")
    expected_tree = proof.get("proof_source_tree_sha256")
    require(isinstance(expected_tree, str) and SHA256_RE.fullmatch(expected_tree) is not None, "proof source digest is malformed")
    require(expected_tree == source_tree_digest(root), "source tree changed since performance proof")
    verify_environment_observations(proof.get("environment"), args.allow_uncontrolled)
    toolchain = proof.get("toolchain")
    require(isinstance(toolchain, dict), "performance proof lacks toolchain identity")
    _strict_keys(
        toolchain,
        {
            "cargo",
            "cargo_path",
            "cargo_sha256",
            "rustc",
            "rustc_path",
            "rustc_sha256",
            "target",
        },
        "performance toolchain",
    )
    try:
        current_budget = load_json_object_snapshot(
            production_budget_path(root),
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="production performance budget",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    current_toolchain, _cargo, _rustc = verified_toolchain(
        root, current_budget.value
    )
    require(toolchain == current_toolchain, "performance proof toolchain differs from current policy-bound toolchain")
    require_toolchain_unchanged(current_toolchain, _cargo, _rustc)
    target = toolchain["target"]
    current_environment = collect_environment()
    for field in ("system", "release", "machine", "cpu"):
        require(
            proof["environment"]["post_analysis"].get(field)
            == current_environment.get(field),
            f"performance environment changed for {field}",
        )
    if not args.allow_uncontrolled:
        verify_environment(current_environment, False)

    artifacts = proof.get("artifacts")
    require(isinstance(artifacts, dict), "performance proof lacks artifacts")
    _strict_keys(
        artifacts,
        {"raw_path", "raw_sha256", "binary_path", "binary_sha256", "budget_path", "budget_sha256"},
        "performance artifacts",
    )
    raw_path = proof_artifact_path(root, artifacts.get("raw_path"), "raw performance data")
    executable = proof_artifact_path(root, artifacts.get("binary_path"), "performance binary")
    budget_path = production_budget_path(root)
    require_distinct_paths(
        {
            "performance proof": proof_path,
            "raw performance data": raw_path,
            "performance binary": executable,
            "performance budget": budget_path,
        }
    )
    raw_expected = artifacts.get("raw_sha256")
    binary_expected = artifacts.get("binary_sha256")
    for field, expected in (
        ("raw_sha256", raw_expected),
        ("binary_sha256", binary_expected),
    ):
        require(
            isinstance(expected, str) and SHA256_RE.fullmatch(expected) is not None,
            f"proof {field} is malformed",
        )
    expected_binary_name = f"paired_profile_perf-{binary_expected}" + (
        ".exe" if os.name == "nt" else ""
    )
    require(
        executable.parent
        == (root / "target" / "performance" / "binaries" / target).resolve()
        and executable.name == expected_binary_name,
        "performance proof names an unexpected evidence binary path",
    )
    raw_snapshot, metadata, grouped = parse_raw_snapshot(raw_path)
    require(raw_snapshot.sha256 == raw_expected, f"performance artifact changed: {raw_path}")
    require(binary_expected == sha256_file(executable), f"performance artifact changed: {executable}")
    budget_snapshot = verified_production_budget_snapshot(root, artifacts)
    require(
        budget_snapshot.file.sha256 == current_budget.file.sha256,
        "performance budget changed during verification",
    )
    analysis = analyse(metadata, grouped, budget_snapshot.value)
    require(proof.get("harness") == metadata, "performance proof harness metadata changed")
    require(proof.get("analysis") == analysis, "performance proof analysis changed")
    require(proof.get("gate") == {"passed": True}, "performance proof is not a passing gate")
    require(expected_tree == source_tree_digest(root), "source tree changed during performance verification")
    if not args.allow_dirty:
        require(not source_tree_dirty(root), "source tree became dirty during performance verification")
    require_toolchain_unchanged(current_toolchain, _cargo, _rustc)
    require(raw_expected == sha256_file(raw_path), "raw performance data changed during verification")
    require(binary_expected == sha256_file(executable), "performance binary changed during verification")
    require(
        current_budget.file.sha256 == sha256_file(budget_path),
        "performance budget changed during verification",
    )
    if manifest_bound:
        manifest_path = pathlib.Path(os.path.abspath(args.results_manifest))
        try:
            final_manifest = load_results_manifest_snapshot(
                manifest_path,
                expected_sha256=args.expected_results_manifest_sha256,
            )
            final_proof = select_bound_json_snapshot(
                root,
                final_manifest,
                binding="performance",
                selected_path=proof_path,
                maximum=MAX_PERFORMANCE_PROOF_BYTES,
                label="performance proof",
            )
        except ProofManifestError as exc:
            raise GateError(str(exc)) from exc
        require(
            final_proof.file.sha256 == proof_snapshot.file.sha256,
            "selected performance proof changed during verification",
        )
    else:
        try:
            final_proof = load_json_object_snapshot(
                proof_path,
                maximum=MAX_PERFORMANCE_PROOF_BYTES,
                label="performance proof",
            )
        except EvidenceIOError as exc:
            raise GateError(str(exc)) from exc
        require(
            final_proof.file.sha256 == proof_snapshot.file.sha256,
            "selected performance proof changed during verification",
        )
    print(f"PAIRED_PROFILE_PERFORMANCE_PROOF_PASS proof={proof_path}")
    if manifest_bound:
        print(
            "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS "
            f"section=performance sha256={proof_snapshot.file.sha256}"
        )


def validate_raw(args: argparse.Namespace) -> None:
    metadata, _grouped = parse_raw(args.raw.resolve())
    print(
        "PAIRED_PROFILE_PERFORMANCE_RAW_SCHEMA_PASS "
        f"samples={metadata['samples_per_profile_operation']} raw={args.raw.resolve()}"
    )


def positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be an integer: {raw}") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be positive: {raw}")
    return value


def bounded_positive_int(maximum: int, label: str) -> Callable[[str], int]:
    def parse(raw: str) -> int:
        value = positive_int(raw)
        if value > maximum:
            raise argparse.ArgumentTypeError(
                f"{label} must not exceed {maximum}: {raw}"
            )
        return value

    return parse


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--root", type=pathlib.Path, required=True)
    collect_parser.add_argument("--raw", type=pathlib.Path, required=True)
    collect_parser.add_argument("--proof", type=pathlib.Path, required=True)
    collect_parser.add_argument(
        "--samples",
        type=bounded_positive_int(MAX_COLLECTION_SAMPLES, "samples"),
        default=20_480,
    )
    collect_parser.add_argument(
        "--warmup-ms",
        type=bounded_positive_int(MAX_COLLECTION_WARMUP_MS, "warmup-ms"),
        default=5_000,
    )
    collect_parser.add_argument("--allow-dirty", action="store_true")
    collect_parser.add_argument("--allow-uncontrolled", action="store_true")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--root", type=pathlib.Path, required=True)
    verify_parser.add_argument("--proof", type=pathlib.Path, required=True)
    verify_parser.add_argument("--max-age-seconds", type=positive_int, default=DEFAULT_MAX_AGE_SECONDS)
    verify_parser.add_argument("--allow-dirty", action="store_true")
    verify_parser.add_argument("--allow-uncontrolled", action="store_true")
    verify_parser.add_argument("--results-manifest", default="")
    verify_parser.add_argument("--expected-results-manifest-sha256", default="")

    raw_parser = subparsers.add_parser("validate-raw")
    raw_parser.add_argument("--raw", type=pathlib.Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "collect":
            collect(args)
        elif args.command == "verify":
            verify(args)
        else:
            validate_raw(args)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
