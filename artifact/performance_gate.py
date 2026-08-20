#!/usr/bin/env python3
"""Collect and verify paired profile and implementation performance evidence."""

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
from typing import Any

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


PROOF_SCHEMA_VERSION = 8
HARNESS_SCHEMA_VERSION = 5
BUDGET_SCHEMA_VERSION = 10
PROFILE_NON_REGRESSION = "profile_non_regression"
IMPLEMENTATION_IMPROVEMENT = "implementation_improvement"
ESTIMANDS = (PROFILE_NON_REGRESSION, IMPLEMENTATION_IMPROVEMENT)
OPERATIONS = ("combine", "encapsulate", "decapsulate")
IMPLEMENTATION_OPERATIONS = ("encapsulate", "decapsulate")
PROFILES = ("ContextBound", "CompatXWing")
IMPLEMENTATIONS = ("native", "portable")
RELEASE_EVIDENCE_MODE = "release_evidence"
PROFILE_DIAGNOSTIC_MODE = "profile_diagnostic"
NATIVE_IMPLEMENTATION_ID = (
    "mlkem-native-1.2.0/aarch64-native-arith+fips202-v84a"
)
PORTABLE_REFERENCE_IMPLEMENTATION_ID = (
    "mlkem-native-1.2.0/portable-c/evidence-only-reference"
)
PORTABLE_REFERENCE_SCOPE = "evidence_only_non_product_reference"
IMPLEMENTATION_SURFACE = "hybrid_core"
IMPLEMENTATION_KEY_FORMAT = "expanded_fips203_2400"
IMPLEMENTATION_KEYPAIR_GENERATION_COUNT = 1
IMPLEMENTATION_INCLUDES_FFI = False
IMPLEMENTATION_INCLUDES_OS_RNG = False
PORTABLE_REFERENCE_SOURCE_RELATIVE = pathlib.PurePosixPath(
    "crates/q-periapt-mlkem-native-sys/src/mlkem_bridge_portable.c"
)
PORTABLE_REFERENCE_ARCHIVE_STEM = "qperiapt_mlkem_portable_evidence"
PORTABLE_REFERENCE_SYMBOLS = tuple(
    f"qpn_mlkem_bridge_v1_2_0_{parameter}_{operation}"
    for parameter in ("512", "768", "1024")
    for operation in (
        "keypair_derand",
        "encapsulate_derand",
        "decapsulate",
        "check_public_key",
    )
)
IMPLEMENTATION_IMPROVEMENT_LIMITS = {
    "max_block_median_p50_ratio_upper_95": 0.95,
    "max_block_median_p95_ratio_upper_95": 0.95,
    "max_block_median_p99_ratio_upper_95": 1.0,
}
EXPECTED_ITERATIONS_PER_SAMPLE = {
    "combine": 256,
    "encapsulate": 1,
    "decapsulate": 2,
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
HEX_BYTES_RE = re.compile(r"^(?:[0-9a-f]{2})*$")
RUSTUP_TOOLCHAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60
MAX_EXACT_ELAPSED_NS_TOTAL = 1 << 53
PRODUCTION_BUDGET_RELATIVE = pathlib.PurePosixPath("artifact/performance-budgets.json")
MAX_PERFORMANCE_PROOF_BYTES = 4 * 1024 * 1024
MAX_PERFORMANCE_BUDGET_BYTES = 1024 * 1024
MAX_PERFORMANCE_RAW_BYTES = 128 * 1024 * 1024
# The release harness emits ten JSONL sample records for each requested sample. This
# cap keeps the producer below the independent 128 MiB raw-evidence bound.
MAX_COLLECTION_SAMPLES = 40_000
MAX_COLLECTION_WARMUP_MS = 60_000
WARMUP_SCOPE = "per_estimand_operation_immediately_before_collection"
XCODE_DEFAULT_TOOLCHAIN_BIN = pathlib.Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin"
)
MACOS_SDK_RELATIVE_TO_DEVELOPER = pathlib.PurePosixPath(
    "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
)
MACOS_SDK_SETTINGS_NAME = "SDKSettings.json"
MACOS_DEPLOYMENT_TARGET = "11.0"
NATIVE_C_ARCHITECTURE = "armv8.4-a+sha3"
PORTABLE_C_ARCHITECTURE = "armv8-a"
C_OPTIMIZATION = "O3"
C_LANGUAGE_STANDARD = "c99"
C_VISIBILITY = "hidden"
RUST_OPTIMIZATION = "O3"
RUST_LTO = "thin"
RUST_CODEGEN_UNITS = 1
MATCHED_C_CODEGEN_FLAGS = (
    f"-{C_OPTIMIZATION}",
    "-fPIC",
    "-ffunction-sections",
    "-fdata-sections",
    f"-mmacosx-version-min={MACOS_DEPLOYMENT_TARGET}",
)


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


def canonical_profile_inputs() -> dict[str, dict[str, Any]]:
    """Return the exact profile-specific inputs admitted by the paired harness."""

    return {
        "ContextBound": {
            "suite_id_hex": b"ML-KEM-768+X25519".hex(),
            "policy_version": 1,
            "application_context_hex": b"q-periapt/performance-gate/v1".hex(),
        },
        "CompatXWing": {
            "suite_id_hex": "",
            "policy_version": 0,
            "application_context_hex": "",
        },
    }


def canonical_build_contract() -> dict[str, Any]:
    """Return the exact matched code-generation contract for release evidence."""

    def c_build(architecture: str) -> dict[str, Any]:
        return {
            "architecture": architecture,
            "data_sections": True,
            "function_sections": True,
            "language_standard": C_LANGUAGE_STANDARD,
            "macos_deployment_target": MACOS_DEPLOYMENT_TARGET,
            "optimization": C_OPTIMIZATION,
            "position_independent_code": True,
            "visibility": C_VISIBILITY,
        }

    return {
        "c_implementations": {
            "product_native": c_build(NATIVE_C_ARCHITECTURE),
            "portable_reference": c_build(PORTABLE_C_ARCHITECTURE),
        },
        "rust_harness": {
            "codegen_units": RUST_CODEGEN_UNITS,
            "lto": RUST_LTO,
            "optimization": RUST_OPTIMIZATION,
        },
    }


def validate_build_contract(value: Any, label: str) -> dict[str, Any]:
    """Fail closed unless every native/reference code-generation input is pinned."""

    require(isinstance(value, dict), f"{label} must be an object")
    _strict_keys(value, {"c_implementations", "rust_harness"}, label)
    c_implementations = value.get("c_implementations")
    require(
        isinstance(c_implementations, dict),
        f"{label}/c_implementations must be an object",
    )
    _strict_keys(
        c_implementations,
        {"product_native", "portable_reference"},
        f"{label}/c_implementations",
    )
    c_fields = {
        "architecture",
        "data_sections",
        "function_sections",
        "language_standard",
        "macos_deployment_target",
        "optimization",
        "position_independent_code",
        "visibility",
    }
    for implementation in ("product_native", "portable_reference"):
        settings = c_implementations.get(implementation)
        require(
            isinstance(settings, dict),
            f"{label}/c_implementations/{implementation} must be an object",
        )
        _strict_keys(
            settings,
            c_fields,
            f"{label}/c_implementations/{implementation}",
        )
        for field in (
            "data_sections",
            "function_sections",
            "position_independent_code",
        ):
            require(
                type(settings.get(field)) is bool,
                f"{label}/c_implementations/{implementation}/{field} must be boolean",
            )
        for field in (
            "architecture",
            "language_standard",
            "macos_deployment_target",
            "optimization",
            "visibility",
        ):
            require(
                isinstance(settings.get(field), str) and bool(settings[field]),
                f"{label}/c_implementations/{implementation}/{field} must be text",
            )
    rust_harness = value.get("rust_harness")
    require(isinstance(rust_harness, dict), f"{label}/rust_harness must be an object")
    _strict_keys(
        rust_harness,
        {"codegen_units", "lto", "optimization"},
        f"{label}/rust_harness",
    )
    require(
        type(rust_harness.get("codegen_units")) is int,
        f"{label}/rust_harness/codegen_units must be an integer",
    )
    for field in ("lto", "optimization"):
        require(
            isinstance(rust_harness.get(field), str) and bool(rust_harness[field]),
            f"{label}/rust_harness/{field} must be text",
        )
    expected = canonical_build_contract()
    require(
        {
            field: value
            for field, value in c_implementations["product_native"].items()
            if field != "architecture"
        }
        == {
            field: value
            for field, value in c_implementations["portable_reference"].items()
            if field != "architecture"
        },
        f"{label} does not compile native and portable C implementations under"
        " the same matched non-architecture codegen contract",
    )
    require(value == expected, f"{label} does not match the canonical build contract")
    return value


def validate_profile_inputs(value: Any, label: str) -> dict[str, Any]:
    """Require the strict nested shape and canonical inputs for both profiles."""

    require(isinstance(value, dict), f"{label} must be an object")
    _strict_keys(value, set(PROFILES), label)
    fields = {"suite_id_hex", "policy_version", "application_context_hex"}
    expected = canonical_profile_inputs()
    for profile in PROFILES:
        profile_inputs = value[profile]
        require(
            isinstance(profile_inputs, dict),
            f"{label}/{profile} must be an object",
        )
        _strict_keys(profile_inputs, fields, f"{label}/{profile}")
        for field in ("suite_id_hex", "application_context_hex"):
            encoded = profile_inputs[field]
            require(
                isinstance(encoded, str)
                and HEX_BYTES_RE.fullmatch(encoded) is not None,
                f"invalid {label}/{profile}/{field}",
            )
        require(
            type(profile_inputs["policy_version"]) is int,
            f"{label}/{profile}/policy_version must be an integer",
        )
        require(
            profile_inputs == expected[profile],
            f"{label}/{profile} does not match the canonical performance inputs",
        )
    return value


def parse_raw_bytes(
    data: bytes,
) -> tuple[
    dict[str, Any],
    dict[tuple[str, str, str], list[dict[str, Any]]],
]:
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
        "build_contract",
        "corpus_size",
        "implementation_improvement",
        "iterations_per_sample",
        "mode",
        "profile_inputs",
        "profile_non_regression",
        "record_type",
        "samples_per_variant_operation",
        "schedule",
        "schema_version",
        "target",
        "warmup_ms",
        "warmup_scope",
    }
    _strict_keys(metadata, metadata_fields, "metadata record")
    require(type(metadata.get("schema_version")) is int, "harness schema must be an integer")
    require(metadata.get("schema_version") == HARNESS_SCHEMA_VERSION, "harness schema mismatch")
    require(metadata.get("record_type") == "metadata", "first JSONL record must be metadata")
    mode = metadata.get("mode")
    require(
        mode in {RELEASE_EVIDENCE_MODE, PROFILE_DIAGNOSTIC_MODE},
        "invalid performance harness mode",
    )
    require(metadata.get("schedule") == "ABBA/BAAB", "unsupported metadata schedule")
    target = metadata.get("target")
    require(
        isinstance(target, str)
        and bool(target)
        and "/" not in target
        and "\\" not in target,
        "invalid metadata target",
    )
    validate_profile_inputs(metadata.get("profile_inputs"), "metadata profile_inputs")
    require(type(metadata.get("warmup_ms")) is int and metadata["warmup_ms"] > 0, "invalid warmup duration")
    require(
        metadata.get("warmup_scope") == WARMUP_SCOPE,
        "metadata warmup scope is invalid",
    )
    iterations_per_sample = positive_operation_map(
        metadata.get("iterations_per_sample"),
        "metadata iterations_per_sample",
    )
    require(
        iterations_per_sample == EXPECTED_ITERATIONS_PER_SAMPLE,
        "metadata iterations_per_sample does not match the harness contract",
    )

    profile_contract = metadata.get(PROFILE_NON_REGRESSION)
    require(
        isinstance(profile_contract, dict),
        "metadata lacks profile_non_regression contract",
    )
    _strict_keys(
        profile_contract,
        {"backend", "direction", "operations", "variants"},
        "profile_non_regression metadata",
    )
    require(
        isinstance(profile_contract.get("backend"), str)
        and bool(profile_contract["backend"]),
        "invalid profile_non_regression backend",
    )
    require(
        profile_contract.get("direction") == "ContextBound/CompatXWing",
        "profile_non_regression direction is invalid",
    )
    require(
        profile_contract.get("operations") == list(OPERATIONS),
        "profile_non_regression operation inventory mismatch",
    )
    require(
        profile_contract.get("variants") == list(PROFILES),
        "profile_non_regression variant inventory mismatch",
    )

    implementation_contract = metadata.get(IMPLEMENTATION_IMPROVEMENT)
    if mode == PROFILE_DIAGNOSTIC_MODE:
        require(
            metadata.get("build_contract") is None,
            "profile diagnostic raw data cannot claim the release build contract",
        )
        require(
            implementation_contract is None,
            "profile diagnostic raw data cannot claim implementation improvement",
        )
    else:
        require(
            target == "aarch64-apple-darwin",
            "release implementation evidence requires aarch64-apple-darwin",
        )
        validate_build_contract(metadata.get("build_contract"), "metadata build_contract")
        require(
            isinstance(implementation_contract, dict),
            "release raw data lacks implementation_improvement contract",
        )
        _strict_keys(
            implementation_contract,
            {
                "digest_algorithm",
                "direction",
                "equivalence_cases_per_operation",
                "includes_ffi",
                "includes_os_rng",
                "key_format",
                "keypair_generation_count",
                "native_implementation_id",
                "operations",
                "portable_implementation_id",
                "product_profile",
                "reference_scope",
                "surface",
                "variants",
            },
            "implementation_improvement metadata",
        )
        require(
            implementation_contract.get("direction") == "native/portable",
            "implementation_improvement direction is invalid",
        )
        require(
            implementation_contract.get("variants") == list(IMPLEMENTATIONS),
            "implementation_improvement variant inventory mismatch",
        )
        require(
            implementation_contract.get("operations")
            == list(IMPLEMENTATION_OPERATIONS),
            "implementation_improvement operation inventory mismatch",
        )
        require(
            implementation_contract.get("product_profile") == "ContextBound",
            "implementation improvement must measure the ContextBound hybrid-core surface",
        )
        expected_surface = {
            "surface": IMPLEMENTATION_SURFACE,
            "key_format": IMPLEMENTATION_KEY_FORMAT,
            "keypair_generation_count": IMPLEMENTATION_KEYPAIR_GENERATION_COUNT,
            "includes_ffi": IMPLEMENTATION_INCLUDES_FFI,
            "includes_os_rng": IMPLEMENTATION_INCLUDES_OS_RNG,
        }
        for field, expected in expected_surface.items():
            actual = implementation_contract.get(field)
            if field in {"includes_ffi", "includes_os_rng"}:
                require(
                    type(actual) is bool,
                    f"implementation improvement {field} must be boolean",
                )
            elif field == "keypair_generation_count":
                require(
                    type(actual) is int,
                    "implementation improvement keypair_generation_count must be an integer",
                )
            require(
                actual == expected,
                f"implementation improvement {field} is invalid",
            )
        require(
            implementation_contract.get("native_implementation_id")
            == NATIVE_IMPLEMENTATION_ID,
            "implementation improvement native identity is invalid",
        )
        require(
            implementation_contract.get("portable_implementation_id")
            == PORTABLE_REFERENCE_IMPLEMENTATION_ID,
            "implementation improvement portable identity is invalid",
        )
        require(
            implementation_contract.get("reference_scope")
            == PORTABLE_REFERENCE_SCOPE,
            "portable implementation is not evidence-only",
        )
        require(
            implementation_contract.get("digest_algorithm") == "SHA3-256",
            "implementation equivalence digest algorithm is invalid",
        )

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    sample_fields = {
        "estimand",
        "schema_version",
        "record_type",
        "operation",
        "variant",
        "pair_id",
        "schedule_index",
        "corpus_index",
        "elapsed_ns_total",
    }
    equivalence_fields = {
        "case_id",
        "corpus_index",
        "input_digest_hex",
        "native_output_digest_hex",
        "operation",
        "portable_output_digest_hex",
        "record_type",
        "schema_version",
    }
    seen: set[tuple[str, str, int, str]] = set()
    equivalence: dict[tuple[str, int], dict[str, Any]] = {}
    for index, record in enumerate(records[1:], start=2):
        record_type = record.get("record_type")
        if record_type == "equivalence":
            _strict_keys(record, equivalence_fields, f"equivalence record {index}")
            require(
                record.get("schema_version") == HARNESS_SCHEMA_VERSION,
                f"equivalence schema mismatch at line {index}",
            )
            operation = record.get("operation")
            require(
                operation in IMPLEMENTATION_OPERATIONS,
                f"unknown equivalence operation at line {index}: {operation}",
            )
            for field in ("case_id", "corpus_index"):
                require(
                    type(record.get(field)) is int and record[field] >= 0,
                    f"{field} must be a non-negative integer at line {index}",
                )
            for field in (
                "input_digest_hex",
                "native_output_digest_hex",
                "portable_output_digest_hex",
            ):
                digest = record.get(field)
                require(
                    isinstance(digest, str)
                    and SHA256_RE.fullmatch(digest) is not None,
                    f"{field} is malformed at line {index}",
                )
            require(
                record["native_output_digest_hex"]
                == record["portable_output_digest_hex"],
                f"implementation outputs differ at line {index}",
            )
            key = (operation, record["case_id"])
            require(key not in equivalence, f"duplicate equivalence record: {key}")
            equivalence[key] = record
            continue
        _strict_keys(record, sample_fields, f"sample record {index}")
        require(type(record.get("schema_version")) is int, f"sample schema must be an integer at line {index}")
        require(record.get("schema_version") == HARNESS_SCHEMA_VERSION, f"sample schema mismatch at line {index}")
        require(record.get("record_type") == "sample", f"non-sample record at line {index}")
        estimand = record.get("estimand")
        operation = record.get("operation")
        variant = record.get("variant")
        require(estimand in ESTIMANDS, f"unknown estimand at line {index}: {estimand}")
        allowed_operations = (
            OPERATIONS
            if estimand == PROFILE_NON_REGRESSION
            else IMPLEMENTATION_OPERATIONS
        )
        allowed_variants = (
            PROFILES
            if estimand == PROFILE_NON_REGRESSION
            else IMPLEMENTATIONS
        )
        require(operation in allowed_operations, f"unknown operation at line {index}: {operation}")
        require(variant in allowed_variants, f"unknown variant at line {index}: {variant}")
        require(
            mode == RELEASE_EVIDENCE_MODE
            or estimand == PROFILE_NON_REGRESSION,
            "profile diagnostic raw data contains implementation samples",
        )
        for field in ("pair_id", "schedule_index", "corpus_index", "elapsed_ns_total"):
            require(type(record.get(field)) is int, f"{field} must be an integer at line {index}")
            require(record[field] >= 0, f"{field} must be non-negative at line {index}")
        require(record["elapsed_ns_total"] > 0, f"elapsed_ns_total must be positive at line {index}")
        require(
            record["elapsed_ns_total"] <= MAX_EXACT_ELAPSED_NS_TOTAL,
            f"elapsed_ns_total exceeds exact analysis range at line {index}",
        )
        key = (estimand, operation, record["pair_id"], variant)
        require(key not in seen, f"duplicate paired sample: {key}")
        seen.add(key)
        grouped[(estimand, operation, variant)].append(record)

    expected_samples = metadata.get("samples_per_variant_operation")
    corpus_size = metadata.get("corpus_size")
    require(type(expected_samples) is int and expected_samples > 0, "invalid metadata sample count")
    require(expected_samples % 2 == 0, "metadata sample count must be even for ABBA/BAAB")
    require(type(corpus_size) is int and corpus_size > 0, "invalid metadata corpus size")
    estimand_contracts = ((PROFILE_NON_REGRESSION, OPERATIONS, PROFILES),)
    if mode == RELEASE_EVIDENCE_MODE:
        estimand_contracts += (
            (IMPLEMENTATION_IMPROVEMENT, IMPLEMENTATION_OPERATIONS, IMPLEMENTATIONS),
        )
    for estimand, operations, variants in estimand_contracts:
        for operation in operations:
            by_pair: dict[int, dict[str, dict[str, Any]]] = defaultdict(dict)
            schedule_records: list[dict[str, Any]] = []
            for variant in variants:
                samples = grouped[(estimand, operation, variant)]
                require(
                    len(samples) == expected_samples,
                    f"{estimand}/{operation}/{variant} has {len(samples)} samples, expected {expected_samples}",
                )
                for record in samples:
                    by_pair[record["pair_id"]][variant] = record
                    schedule_records.append(record)
            require(
                set(by_pair) == set(range(expected_samples)),
                f"{estimand}/{operation} pair ids are not contiguous",
            )
            for pair_id, pair in by_pair.items():
                require(
                    set(pair) == set(variants),
                    f"{estimand}/{operation} pair {pair_id} is incomplete",
                )
                for record in pair.values():
                    require(
                        record["corpus_index"] == pair_id % corpus_size,
                        f"{estimand}/{operation} pair {pair_id} has the wrong corpus index",
                    )
            ordered = sorted(
                schedule_records,
                key=lambda record: record["schedule_index"],
            )
            require(
                [record["schedule_index"] for record in ordered]
                == list(range(expected_samples * 2)),
                f"{estimand}/{operation} schedule indexes are not contiguous",
            )
            for cycle in range(expected_samples // 2):
                actual_order = [
                    (record["variant"], record["pair_id"])
                    for record in ordered[cycle * 4 : cycle * 4 + 4]
                ]
                first_pair = cycle * 2
                left, right = variants
                expected_order = (
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
                require(
                    actual_order == expected_order,
                    f"{estimand}/{operation} schedule cycle {cycle} is not ABBA/BAAB",
                )

    if mode == PROFILE_DIAGNOSTIC_MODE:
        require(not equivalence, "profile diagnostic raw data contains equivalence records")
    else:
        expected_equivalence_counts = {
            "encapsulate": corpus_size,
            "decapsulate": corpus_size,
        }
        require(
            implementation_contract.get("equivalence_cases_per_operation")
            == expected_equivalence_counts,
            "implementation equivalence case inventory mismatch",
        )
        for operation, count in expected_equivalence_counts.items():
            require(
                {
                    case_id
                    for (record_operation, case_id) in equivalence
                    if record_operation == operation
                }
                == set(range(count)),
                f"{operation} equivalence case ids are not contiguous",
            )
            for case_id in range(count):
                record = equivalence[(operation, case_id)]
                require(
                    record["corpus_index"] == case_id,
                    f"{operation} equivalence case {case_id} has the wrong corpus index",
                )

    return metadata, grouped


def parse_raw_snapshot(
    path: pathlib.Path,
) -> tuple[
    FileSnapshot,
    dict[str, Any],
    dict[tuple[str, str, str], list[dict[str, Any]]],
]:
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


def parse_raw(
    path: pathlib.Path,
) -> tuple[
    dict[str, Any],
    dict[tuple[str, str, str], list[dict[str, Any]]],
]:
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


def expected_operation_budget_fields(
    estimand: str,
    operation: str,
) -> set[str]:
    ratio_and_delta_fields = {
        "max_block_median_p50_ratio_upper_95",
        "max_block_median_p95_ratio_upper_95",
        "max_block_median_p99_ratio_upper_95",
        "max_block_median_p95_delta_ns_upper_95",
    }
    if estimand == IMPLEMENTATION_IMPROVEMENT:
        return set(IMPLEMENTATION_IMPROVEMENT_LIMITS)
    require(
        estimand == PROFILE_NON_REGRESSION and operation in OPERATIONS,
        "unknown performance budget estimand or operation",
    )
    return (
        {"max_block_median_p95_delta_ns_upper_95"}
        if operation == "combine"
        else ratio_and_delta_fields
    )


def validate_operation_budget_policy(
    estimand: str,
    operations: tuple[str, ...],
    value: Any,
) -> None:
    require(isinstance(value, dict), f"{estimand} budget operations must be an object")
    _strict_keys(value, set(operations), f"{estimand} budget operation inventory")
    for operation in operations:
        operation_budget = value.get(operation)
        require(
            isinstance(operation_budget, dict),
            f"budget for {estimand}/{operation} must be an object",
        )
        expected_fields = expected_operation_budget_fields(estimand, operation)
        _strict_keys(
            operation_budget,
            expected_fields,
            f"budget for {estimand}/{operation}",
        )
        for metric in expected_fields:
            actual = finite_number(
                operation_budget.get(metric),
                f"budget {estimand}/{operation}/{metric}",
            )
            require(
                actual > 0,
                f"budget {estimand}/{operation}/{metric} must be positive",
            )
            if estimand == IMPLEMENTATION_IMPROVEMENT:
                expected = IMPLEMENTATION_IMPROVEMENT_LIMITS[metric]
                require(
                    actual == expected,
                    f"implementation_improvement budget {operation}/{metric} "
                    f"must remain preregistered at {expected}",
                )


def validate_budget_layout(
    budget: dict[str, Any],
    *,
    samples: int,
    corpus_size: int,
) -> None:
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
    require(
        type(bootstrap_span) is int and bootstrap_span > 0,
        "invalid bootstrap estimate-block span",
    )
    require(
        bootstrap_span <= samples // pair_block_size,
        "bootstrap estimate-block span exceeds the paired estimate-block count",
    )


def validate_budget_policy(budget: dict[str, Any]) -> tuple[int, int, int]:
    """Validate the complete preregistered policy before collection or analysis."""

    expected_fields = {
        "bootstrap_estimate_block_span",
        "build_contract",
        "collection_samples_per_variant_operation",
        "corpus_size",
        "harness_schema_version",
        "implementation_improvement",
        "iterations_per_sample",
        "max_block_median_cv",
        "min_p99_tail_observations_per_pair_block",
        "min_samples_per_variant_operation",
        "mode",
        "pair_block_size",
        "profile_inputs",
        "profile_non_regression",
        "regression_guard_pair_block_size",
        "schedule",
        "schema_version",
        "stability_block_sizes",
        "target",
        "toolchain",
        "warmup_ms",
        "warmup_scope",
    }
    _strict_keys(budget, expected_fields, "performance budget")
    require(type(budget.get("schema_version")) is int, "performance budget schema must be an integer")
    require(
        budget.get("schema_version") == BUDGET_SCHEMA_VERSION,
        "performance budget schema mismatch",
    )
    require(type(budget.get("harness_schema_version")) is int, "budget harness schema must be an integer")
    require(budget.get("harness_schema_version") == HARNESS_SCHEMA_VERSION, "budget harness schema mismatch")
    validate_profile_inputs(budget.get("profile_inputs"), "budget profile_inputs")
    validate_build_contract(budget.get("build_contract"), "budget build_contract")
    toolchain_policy = validate_toolchain_policy(budget.get("toolchain"))
    require(
        budget.get("mode") == RELEASE_EVIDENCE_MODE,
        "performance budget must require release evidence mode",
    )
    require(
        budget.get("schedule") == "ABBA/BAAB",
        "performance budget schedule mismatch",
    )
    require(
        budget.get("target") == toolchain_policy.get("target"),
        "performance budget target differs from toolchain target",
    )
    require(
        budget.get("target") == "aarch64-apple-darwin",
        "performance budget target must remain aarch64-apple-darwin",
    )
    budget_iterations = positive_operation_map(
        budget.get("iterations_per_sample"),
        "budget iterations_per_sample",
    )
    require(
        budget_iterations == EXPECTED_ITERATIONS_PER_SAMPLE,
        "budget iterations_per_sample does not match the harness contract",
    )
    minimum = budget.get("min_samples_per_variant_operation")
    require(type(minimum) is int and minimum > 0, "invalid minimum sample budget")
    collection_samples = budget.get("collection_samples_per_variant_operation")
    require(
        type(collection_samples) is int and collection_samples >= minimum,
        "invalid exact collection sample budget",
    )
    require(
        collection_samples <= MAX_COLLECTION_SAMPLES,
        "performance budget sample count exceeds the collector resource limit",
    )
    warmup = budget.get("warmup_ms")
    require(type(warmup) is int and warmup > 0, "invalid warmup budget")
    require(
        warmup <= MAX_COLLECTION_WARMUP_MS,
        "performance budget warmup exceeds the collector resource limit",
    )
    require(
        budget.get("warmup_scope") == WARMUP_SCOPE,
        "performance budget warmup scope mismatch",
    )
    corpus_size = budget.get("corpus_size")
    require(
        type(corpus_size) is int and corpus_size > 0,
        "invalid performance budget corpus size",
    )
    validate_budget_layout(
        budget,
        samples=collection_samples,
        corpus_size=corpus_size,
    )
    profile_budget = budget.get(PROFILE_NON_REGRESSION)
    require(
        isinstance(profile_budget, dict),
        "performance budget lacks profile_non_regression",
    )
    _strict_keys(
        profile_budget,
        {"backend", "direction", "operations"},
        "profile_non_regression budget",
    )
    require(
        isinstance(profile_budget.get("backend"), str)
        and bool(profile_budget["backend"]),
        "profile_non_regression budget backend is invalid",
    )
    require(
        profile_budget.get("direction") == "ContextBound/CompatXWing",
        "profile_non_regression budget direction mismatch",
    )
    validate_operation_budget_policy(
        PROFILE_NON_REGRESSION,
        OPERATIONS,
        profile_budget.get("operations"),
    )

    implementation_budget = budget.get(IMPLEMENTATION_IMPROVEMENT)
    require(
        isinstance(implementation_budget, dict),
        "performance budget lacks implementation_improvement",
    )
    _strict_keys(
        implementation_budget,
        {
            "direction",
            "includes_ffi",
            "includes_os_rng",
            "key_format",
            "keypair_generation_count",
            "native_implementation_id",
            "operations",
            "portable_implementation_id",
            "product_profile",
            "reference_scope",
            "surface",
        },
        "implementation_improvement budget",
    )
    expected_implementation_contract = {
        "direction": "native/portable",
        "includes_ffi": IMPLEMENTATION_INCLUDES_FFI,
        "includes_os_rng": IMPLEMENTATION_INCLUDES_OS_RNG,
        "key_format": IMPLEMENTATION_KEY_FORMAT,
        "keypair_generation_count": IMPLEMENTATION_KEYPAIR_GENERATION_COUNT,
        "native_implementation_id": NATIVE_IMPLEMENTATION_ID,
        "portable_implementation_id": PORTABLE_REFERENCE_IMPLEMENTATION_ID,
        "product_profile": "ContextBound",
        "reference_scope": PORTABLE_REFERENCE_SCOPE,
        "surface": IMPLEMENTATION_SURFACE,
    }
    for field in ("includes_ffi", "includes_os_rng"):
        require(
            type(implementation_budget.get(field)) is bool,
            f"implementation_improvement budget {field} must be boolean",
        )
    require(
        type(implementation_budget.get("keypair_generation_count")) is int,
        "implementation_improvement budget keypair_generation_count must be an integer",
    )
    for field, expected in expected_implementation_contract.items():
        require(
            implementation_budget.get(field) == expected,
            f"implementation_improvement budget {field} mismatch",
        )
    validate_operation_budget_policy(
        IMPLEMENTATION_IMPROVEMENT,
        IMPLEMENTATION_OPERATIONS,
        implementation_budget.get("operations"),
    )
    maximum_cv = finite_number(budget.get("max_block_median_cv"), "maximum block-median CV")
    require(0 < maximum_cv <= 1, "maximum block-median CV must be in (0, 1]")
    return minimum, collection_samples, warmup


def validate_budget(metadata: dict[str, Any], budget: dict[str, Any]) -> None:
    minimum, collection_samples, warmup = validate_budget_policy(budget)
    for field in (
        "mode",
        "schedule",
        "target",
        "corpus_size",
        "profile_inputs",
        "build_contract",
        "warmup_scope",
    ):
        require(metadata.get(field) == budget.get(field), f"metadata/budget mismatch for {field}")
    require(
        metadata.get("iterations_per_sample") == EXPECTED_ITERATIONS_PER_SAMPLE,
        "metadata/budget mismatch for iterations_per_sample",
    )
    samples = metadata.get("samples_per_variant_operation")
    require(
        type(samples) is int
        and samples >= minimum
        and samples == collection_samples,
        "sample count differs from the preregistered exact collection policy",
    )
    require(metadata.get("warmup_ms") == warmup, "metadata/budget mismatch for warmup_ms")

    profile_budget = budget[PROFILE_NON_REGRESSION]
    profile_metadata = metadata.get(PROFILE_NON_REGRESSION)
    require(
        isinstance(profile_metadata, dict)
        and profile_metadata.get("backend") == profile_budget.get("backend"),
        "metadata/budget mismatch for profile_non_regression backend",
    )
    require(
        profile_metadata.get("direction") == profile_budget.get("direction"),
        "metadata/budget mismatch for profile_non_regression direction",
    )

    implementation_metadata = metadata.get(IMPLEMENTATION_IMPROVEMENT)
    require(
        isinstance(implementation_metadata, dict),
        "release metadata lacks implementation_improvement",
    )
    for field in (
        "direction",
        "includes_ffi",
        "includes_os_rng",
        "key_format",
        "keypair_generation_count",
        "native_implementation_id",
        "portable_implementation_id",
        "product_profile",
        "reference_scope",
        "surface",
    ):
        require(
            implementation_metadata.get(field)
            == budget[IMPLEMENTATION_IMPROVEMENT].get(field),
            f"metadata/budget mismatch for implementation_improvement {field}",
        )


def collection_parameters_from_budget(
    budget: dict[str, Any],
) -> tuple[int, int]:
    """Return the preregistered release collection size and warmup policy.

    The release collector must not accept these values from its command line. The
    complete budget policy is validated before any harness process starts.
    """

    _minimum, samples, warmup_ms = validate_budget_policy(budget)
    return samples, warmup_ms


def canonical_absolute_tool_path(value: str, name: str, label: str) -> pathlib.Path:
    pure = pathlib.PurePosixPath(value)
    require(
        pure.is_absolute()
        and pure.as_posix() == value
        and ".." not in pure.parts
        and "\\" not in value
        and "\x00" not in value,
        f"{label} is not a canonical absolute path",
    )
    require(pure.name == name, f"{label} must name {name}")
    return pathlib.Path(value)


def validate_xcode_tool_path(value: str, name: str, label: str) -> pathlib.Path:
    path = canonical_absolute_tool_path(value, name, label)
    expected = XCODE_DEFAULT_TOOLCHAIN_BIN / name
    require(path == expected, f"{label} must be the pinned Xcode {name} executable")
    return path


def macos_sdk_path_for_toolchain(toolchain_bin: pathlib.Path) -> pathlib.Path:
    require(
        len(toolchain_bin.parents) >= 4,
        "Xcode toolchain path cannot identify its Developer directory",
    )
    developer = toolchain_bin.parents[3]
    return developer.joinpath(*MACOS_SDK_RELATIVE_TO_DEVELOPER.parts)


def inspect_macos_sdk(toolchain_bin: pathlib.Path) -> tuple[pathlib.Path, str, str]:
    sdk_path = macos_sdk_path_for_toolchain(toolchain_bin)
    require(
        sdk_path.is_dir() and not sdk_path.is_symlink(),
        "pinned macOS SDK is missing or unsafe",
    )
    try:
        resolved_sdk = sdk_path.resolve(strict=True)
    except OSError as exc:
        raise GateError(f"cannot resolve pinned macOS SDK: {exc}") from exc
    require(resolved_sdk == sdk_path, "pinned macOS SDK path is not canonical")
    settings_path = sdk_path / MACOS_SDK_SETTINGS_NAME
    try:
        settings = read_regular_snapshot(
            settings_path,
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="macOS SDK settings",
        )
        parsed = parse_strict_json_bytes(
            settings.data,
            label="macOS SDK settings",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    require(isinstance(parsed, dict), "macOS SDK settings must be an object")
    version = parsed.get("Version")
    require(
        isinstance(version, str) and bool(version),
        "macOS SDK settings lack Version",
    )
    require_single_line(version, "macOS SDK version")
    return sdk_path, version, settings.sha256


def validate_macos_sdk_path(value: str, label: str) -> pathlib.Path:
    path = canonical_absolute_tool_path(value, "MacOSX.sdk", label)
    expected = macos_sdk_path_for_toolchain(XCODE_DEFAULT_TOOLCHAIN_BIN)
    require(path == expected, f"{label} must name the pinned macOS SDK")
    return path


def require_single_line(value: str, label: str) -> None:
    require(
        bool(value) and "\n" not in value and "\r" not in value and "\x00" not in value,
        f"{label} must be a non-empty single line",
    )


def validate_toolchain_policy(value: Any) -> dict[str, str]:
    require(isinstance(value, dict), "performance budget lacks toolchain policy")
    expected = {
        "ar_path",
        "ar_sha256",
        "cargo_sha256",
        "cargo_version",
        "clang_path",
        "clang_sha256",
        "clang_version",
        "rustc_sha256",
        "rustc_version",
        "rustup_toolchain",
        "sdk_path",
        "sdk_settings_sha256",
        "sdk_version",
        "target",
    }
    _strict_keys(value, expected, "performance toolchain policy")
    for field in expected:
        item = value.get(field)
        require(
            isinstance(item, str) and bool(item),
            f"toolchain policy {field} is missing",
        )
    for field in (
        "ar_sha256",
        "cargo_sha256",
        "clang_sha256",
        "rustc_sha256",
        "sdk_settings_sha256",
    ):
        require(
            SHA256_RE.fullmatch(value[field]) is not None,
            f"toolchain policy {field} is malformed",
        )
    for field in ("cargo_version", "clang_version", "rustc_version", "sdk_version"):
        require_single_line(value[field], f"toolchain policy {field}")
    validate_xcode_tool_path(
        value["clang_path"], "clang", "toolchain policy clang_path"
    )
    validate_xcode_tool_path(value["ar_path"], "ar", "toolchain policy ar_path")
    validate_macos_sdk_path(value["sdk_path"], "toolchain policy sdk_path")
    require(
        RUSTUP_TOOLCHAIN_RE.fullmatch(value["rustup_toolchain"]) is not None,
        "toolchain policy rustup_toolchain is malformed",
    )
    require(
        "/" not in value["target"] and "\\" not in value["target"],
        "toolchain target is malformed",
    )
    return value


def validate_toolchain_identity(value: Any) -> dict[str, str]:
    require(isinstance(value, dict), "performance proof lacks toolchain identity")
    expected = {
        "ar_path",
        "ar_sha256",
        "cargo",
        "cargo_path",
        "cargo_sha256",
        "clang",
        "clang_path",
        "clang_sha256",
        "rustc",
        "rustc_path",
        "rustc_sha256",
        "sdk_path",
        "sdk_settings_sha256",
        "sdk_version",
        "target",
    }
    _strict_keys(value, expected, "performance toolchain")
    for field in expected:
        item = value.get(field)
        require(
            isinstance(item, str) and bool(item),
            f"performance toolchain {field} is missing",
        )
    for field in (
        "ar_sha256",
        "cargo_sha256",
        "clang_sha256",
        "rustc_sha256",
        "sdk_settings_sha256",
    ):
        require(
            SHA256_RE.fullmatch(value[field]) is not None,
            f"performance toolchain {field} is malformed",
        )
    for field in ("cargo", "clang", "rustc", "sdk_version"):
        require_single_line(value[field], f"performance toolchain {field}")
    canonical_absolute_tool_path(
        value["cargo_path"], "cargo", "performance toolchain cargo_path"
    )
    canonical_absolute_tool_path(
        value["rustc_path"], "rustc", "performance toolchain rustc_path"
    )
    validate_xcode_tool_path(
        value["clang_path"], "clang", "performance toolchain clang_path"
    )
    validate_xcode_tool_path(
        value["ar_path"], "ar", "performance toolchain ar_path"
    )
    validate_macos_sdk_path(value["sdk_path"], "performance toolchain sdk_path")
    require(
        "/" not in value["target"] and "\\" not in value["target"],
        "performance toolchain target is malformed",
    )
    return value


def analyse(
    metadata: dict[str, Any],
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]],
    budget: dict[str, Any],
) -> dict[str, Any]:
    validate_budget(metadata, budget)
    return {
        PROFILE_NON_REGRESSION: analyse_estimand(
            metadata,
            grouped,
            budget,
            estimand=PROFILE_NON_REGRESSION,
            operations=OPERATIONS,
            variants=PROFILES,
            operation_budgets=budget[PROFILE_NON_REGRESSION]["operations"],
        ),
        IMPLEMENTATION_IMPROVEMENT: analyse_estimand(
            metadata,
            grouped,
            budget,
            estimand=IMPLEMENTATION_IMPROVEMENT,
            operations=IMPLEMENTATION_OPERATIONS,
            variants=IMPLEMENTATIONS,
            operation_budgets=budget[IMPLEMENTATION_IMPROVEMENT]["operations"],
        ),
    }


def analyse_estimand(
    metadata: dict[str, Any],
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]],
    budget: dict[str, Any],
    *,
    estimand: str,
    operations: tuple[str, ...],
    variants: tuple[str, str],
    operation_budgets: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Analyse one independently named paired estimand."""

    pair_block_size = budget["pair_block_size"]
    regression_guard_pair_block_size = budget["regression_guard_pair_block_size"]
    stability_block_sizes = budget["stability_block_sizes"]
    bootstrap_span = budget["bootstrap_estimate_block_span"]
    max_cv = finite_number(budget["max_block_median_cv"], "maximum block-median CV")
    iterations_per_sample = metadata["iterations_per_sample"]
    result: dict[str, Any] = {}

    for operation in operations:
        by_variant_pair: dict[str, dict[int, float]] = {}
        variant_summary: dict[str, Any] = {}
        max_observed_cv = 0.0
        for variant in variants:
            iterations = iterations_per_sample[operation]
            pair_map = {
                int(record["pair_id"]): float(record["elapsed_ns_total"]) / iterations
                for record in grouped[(estimand, operation, variant)]
            }
            by_variant_pair[variant] = pair_map
            sample_count = int(metadata["samples_per_variant_operation"])
            values = [pair_map[pair_id] for pair_id in range(sample_count)]
            stability_block_size = stability_block_sizes[operation]
            block_medians = [
                percentile(values[offset : offset + stability_block_size], 50)
                for offset in range(0, len(values), stability_block_size)
            ]
            cv = coefficient_of_variation(block_medians)
            max_observed_cv = max(max_observed_cv, cv)
            variant_summary[variant] = {
                "p50_ns": percentile(values, 50),
                "p95_ns": percentile(values, 95),
                "p99_ns": percentile(values, 99),
                "block_median_cv": cv,
            }
        require(
            max_observed_cv <= max_cv,
            f"INVALID_ENV {estimand}/{operation} block-median CV "
            f"{max_observed_cv:.6f} exceeds {max_cv:.6f}",
        )

        sample_count = int(metadata["samples_per_variant_operation"])
        numerator, denominator = variants
        global_descriptive = {
            "p50_ratio": variant_summary[numerator]["p50_ns"]
            / variant_summary[denominator]["p50_ns"],
            "p95_ratio": variant_summary[numerator]["p95_ns"]
            / variant_summary[denominator]["p95_ns"],
            "p99_ratio": variant_summary[numerator]["p99_ns"]
            / variant_summary[denominator]["p99_ns"],
            "p95_delta_ns": variant_summary[numerator]["p95_ns"]
            - variant_summary[denominator]["p95_ns"],
        }
        paired = paired_block_metrics(
            f"{estimand}/{operation}",
            by_variant_pair,
            numerator=numerator,
            denominator=denominator,
            sample_count=sample_count,
            pair_block_size=pair_block_size,
            bootstrap_span=bootstrap_span,
        )
        regression_guard_paired = paired_block_metrics(
            f"{estimand}/{operation}",
            by_variant_pair,
            numerator=numerator,
            denominator=denominator,
            sample_count=sample_count,
            pair_block_size=regression_guard_pair_block_size,
            bootstrap_span=bootstrap_span,
        )

        operation_budget = operation_budgets[operation]
        require(isinstance(operation_budget, dict), f"budget for {operation} must be an object")
        expected_budget_fields = expected_operation_budget_fields(
            estimand,
            operation,
        )
        require(
            set(operation_budget) == expected_budget_fields,
            f"budget for {operation} metric inventory mismatch: expected {sorted(expected_budget_fields)}",
        )
        budget_operation = f"{estimand}/{operation}"
        enforce_operation_budget(
            budget_operation,
            operation_budget,
            paired,
            "primary",
        )
        enforce_operation_budget(
            budget_operation,
            operation_budget,
            regression_guard_paired,
            "regression_guard",
        )
        result[operation] = {
            "variants": variant_summary,
            "direction": f"{numerator}/{denominator}",
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
    by_variant_pair: dict[str, dict[int, float]],
    *,
    numerator: str,
    denominator: str,
    sample_count: int,
    pair_block_size: int,
    bootstrap_span: int,
) -> dict[str, float]:
    """Compute one block-scale paired estimand from the same ordered samples."""

    block_ratios: dict[int, list[float]] = {50: [], 95: [], 99: []}
    block_p95_deltas: list[float] = []
    for offset in range(0, sample_count, pair_block_size):
        pair_ids = range(offset, offset + pair_block_size)
        numerator_values = [
            by_variant_pair[numerator][pair_id] for pair_id in pair_ids
        ]
        denominator_values = [
            by_variant_pair[denominator][pair_id] for pair_id in pair_ids
        ]
        for percent in (50, 95, 99):
            denominator_percentile = percentile(denominator_values, percent)
            require(
                denominator_percentile > 0,
                f"{operation} {denominator} p{percent} is not positive",
            )
            block_ratios[percent].append(
                percentile(numerator_values, percent) / denominator_percentile
            )
        block_p95_deltas.append(
            percentile(numerator_values, 95)
            - percentile(denominator_values, 95)
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


def rustc_macos_deployment_target(
    root: pathlib.Path,
    rustc: pathlib.Path,
    target: str,
    *,
    environment: dict[str, str],
) -> str:
    output = run_line(
        [str(rustc), "--print", "deployment-target", "--target", target],
        root,
        environment=environment,
    )
    expected = f"MACOSX_DEPLOYMENT_TARGET={MACOS_DEPLOYMENT_TARGET}"
    require(output == expected, "rustc deployment target differs from performance policy")
    return MACOS_DEPLOYMENT_TARGET


def binary_path(target_dir: pathlib.Path, target: str) -> pathlib.Path:
    suffix = ".exe" if os.name == "nt" else ""
    return target_dir / target / "release" / "examples" / f"paired_profile_perf{suffix}"


def first_command_line(
    args: list[str],
    root: pathlib.Path,
    *,
    environment: dict[str, str],
    label: str,
) -> str:
    output = run_line(args, root, environment=environment)
    lines = output.splitlines()
    require(bool(lines) and bool(lines[0]), f"{label} did not report a version")
    return lines[0]


def inspect_pinned_executable(
    candidate: pathlib.Path,
    *,
    trusted_parent: pathlib.Path,
    name: str,
    expected_sha256: str,
) -> pathlib.Path:
    require(
        candidate.is_file()
        and not candidate.is_symlink()
        and os.access(candidate, os.X_OK),
        f"pinned performance {name} executable is missing or unsafe",
    )
    try:
        resolved_candidate = candidate.resolve(strict=True)
        candidate_sha256 = sha256_file(resolved_candidate)
    except (GateError, OSError) as exc:
        raise GateError(
            f"cannot inspect pinned performance {name} executable: {exc}"
        ) from exc
    require(
        resolved_candidate == candidate,
        f"pinned performance {name} executable path is not canonical",
    )
    require(
        resolved_candidate.parent == trusted_parent,
        f"pinned performance {name} executable escaped its trusted toolchain",
    )
    require(
        candidate_sha256 == expected_sha256,
        f"pinned performance {name} executable differs from toolchain policy",
    )
    return resolved_candidate


def verified_toolchain(
    root: pathlib.Path, budget: dict[str, Any]
) -> tuple[
    dict[str, str],
    pathlib.Path,
    pathlib.Path,
    pathlib.Path,
    pathlib.Path,
]:
    policy = validate_toolchain_policy(budget.get("toolchain"))
    account_home = account_home_directory()
    rustup_home = account_home / ".rustup"
    require(
        rustup_home.is_dir() and not rustup_home.is_symlink(),
        "performance rustup home is missing or unsafe",
    )
    rustup_toolchains = rustup_home / "toolchains"
    require(
        rustup_toolchains.is_dir() and not rustup_toolchains.is_symlink(),
        "performance rustup toolchain root is missing or unsafe",
    )
    selected_toolchain = rustup_toolchains / policy["rustup_toolchain"]
    require(
        selected_toolchain.is_dir() and not selected_toolchain.is_symlink(),
        "pinned performance rustup toolchain is missing or unsafe",
    )
    selected_bin = selected_toolchain / "bin"
    require(
        selected_bin.is_dir() and not selected_bin.is_symlink(),
        "pinned performance rustup toolchain bin directory is missing or unsafe",
    )
    try:
        resolved_rustup_home = rustup_home.resolve(strict=True)
        resolved_toolchains = rustup_toolchains.resolve(strict=True)
        resolved_toolchain = selected_toolchain.resolve(strict=True)
        resolved_bin = selected_bin.resolve(strict=True)
    except OSError as exc:
        raise GateError(f"cannot resolve pinned performance rustup toolchain: {exc}") from exc
    require(
        resolved_rustup_home.parent == account_home,
        "performance rustup home escaped the trusted account home",
    )
    require(
        resolved_toolchains.parent == resolved_rustup_home,
        "performance rustup toolchain root escaped the trusted rustup home",
    )
    require(
        resolved_toolchain.parent == resolved_toolchains,
        "pinned performance rustup toolchain escaped its trusted root",
    )
    require(
        resolved_bin.parent == resolved_toolchain,
        "pinned performance rustup toolchain bin directory escaped its trusted root",
    )

    resolved: dict[str, pathlib.Path] = {}
    for name in ("cargo", "rustc"):
        resolved[name] = inspect_pinned_executable(
            selected_bin / name,
            trusted_parent=resolved_bin,
            name=name,
            expected_sha256=policy[f"{name}_sha256"],
        )

    require(
        XCODE_DEFAULT_TOOLCHAIN_BIN.is_dir()
        and not XCODE_DEFAULT_TOOLCHAIN_BIN.is_symlink(),
        "pinned Xcode toolchain bin directory is missing or unsafe",
    )
    try:
        resolved_xcode_bin = XCODE_DEFAULT_TOOLCHAIN_BIN.resolve(strict=True)
    except OSError as exc:
        raise GateError(f"cannot resolve pinned Xcode toolchain: {exc}") from exc
    require(
        resolved_xcode_bin == XCODE_DEFAULT_TOOLCHAIN_BIN,
        "pinned Xcode toolchain bin directory is not canonical",
    )
    for name in ("clang", "ar"):
        candidate = pathlib.Path(policy[f"{name}_path"])
        resolved[name] = inspect_pinned_executable(
            candidate,
            trusted_parent=resolved_xcode_bin,
            name=name,
            expected_sha256=policy[f"{name}_sha256"],
        )
    sdk_path, sdk_version, sdk_settings_sha256 = inspect_macos_sdk(
        resolved_xcode_bin
    )
    require(
        str(sdk_path) == policy["sdk_path"],
        "macOS SDK path differs from performance policy",
    )
    require(
        sdk_version == policy["sdk_version"],
        "macOS SDK version differs from performance policy",
    )
    require(
        sdk_settings_sha256 == policy["sdk_settings_sha256"],
        "macOS SDK settings differ from performance policy",
    )

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
    # Apple clang's first line is the compiler version; later lines include the
    # host-derived target triple. Apple ar has no successful version flag, so
    # its canonical path and file digest are its complete policy identity.
    clang_version = first_command_line(
        [str(resolved["clang"]), "--version"],
        root,
        environment=command_environment,
        label="clang",
    )
    target = host_target(
        root, str(resolved["rustc"]), environment=command_environment
    )
    rustc_macos_deployment_target(
        root,
        resolved["rustc"],
        target,
        environment=command_environment,
    )
    identity = {
        "ar_path": str(resolved["ar"]),
        "ar_sha256": sha256_file(resolved["ar"]),
        "cargo": cargo_version,
        "cargo_path": str(resolved["cargo"]),
        "cargo_sha256": sha256_file(resolved["cargo"]),
        "clang": clang_version,
        "clang_path": str(resolved["clang"]),
        "clang_sha256": sha256_file(resolved["clang"]),
        "rustc": rustc_version,
        "rustc_path": str(resolved["rustc"]),
        "rustc_sha256": sha256_file(resolved["rustc"]),
        "sdk_path": str(sdk_path),
        "sdk_settings_sha256": sdk_settings_sha256,
        "sdk_version": sdk_version,
        "target": target,
    }
    validate_toolchain_identity(identity)
    require(cargo_version == policy["cargo_version"], "cargo version differs from performance policy")
    require(rustc_version == policy["rustc_version"], "rustc version differs from performance policy")
    require(clang_version == policy["clang_version"], "clang version differs from performance policy")
    require(target == policy["target"], "rustc target differs from performance policy")
    for name in ("cargo", "rustc", "clang", "ar"):
        require(
            identity[f"{name}_sha256"] == policy[f"{name}_sha256"],
            f"pinned performance {name} executable changed during toolchain inspection",
        )
    return (
        identity,
        resolved["cargo"],
        resolved["rustc"],
        resolved["clang"],
        resolved["ar"],
    )


def require_toolchain_unchanged(
    root: pathlib.Path,
    toolchain: dict[str, str],
    cargo: pathlib.Path,
    rustc: pathlib.Path,
    clang: pathlib.Path,
    ar: pathlib.Path,
) -> None:
    """Detect ordinary tool replacement across a collection or verification window."""

    validate_toolchain_identity(toolchain)
    paths = {"cargo": cargo, "rustc": rustc, "clang": clang, "ar": ar}
    for name, path in paths.items():
        expected_path = canonical_absolute_tool_path(
            toolchain[f"{name}_path"], name, f"performance toolchain {name}_path"
        )
        require(path == expected_path, f"{name} executable path changed")
        require(
            path.is_file()
            and not path.is_symlink()
            and os.access(path, os.X_OK),
            f"{name} executable became unsafe",
        )
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as exc:
            raise GateError(f"cannot revalidate {name} executable: {exc}") from exc
        require(resolved_path == path, f"{name} executable path became non-canonical")
        require(
            sha256_file(path) == toolchain[f"{name}_sha256"],
            f"{name} executable changed during performance evidence processing",
        )
    sdk_path, sdk_version, sdk_settings_sha256 = inspect_macos_sdk(clang.parent)
    require(
        str(sdk_path) == toolchain["sdk_path"],
        "macOS SDK path changed during performance evidence processing",
    )
    require(
        sdk_version == toolchain["sdk_version"],
        "macOS SDK version changed during performance evidence processing",
    )
    require(
        sdk_settings_sha256 == toolchain["sdk_settings_sha256"],
        "macOS SDK settings changed during performance evidence processing",
    )

    command_environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LC_ALL": "C",
        "LANG": "C",
    }
    require(
        run_line([str(cargo), "--version"], root, environment=command_environment)
        == toolchain["cargo"],
        "cargo version changed during performance evidence processing",
    )
    require(
        run_line([str(rustc), "--version"], root, environment=command_environment)
        == toolchain["rustc"],
        "rustc version changed during performance evidence processing",
    )
    require(
        first_command_line(
            [str(clang), "--version"],
            root,
            environment=command_environment,
            label="clang",
        )
        == toolchain["clang"],
        "clang version changed during performance evidence processing",
    )
    require(
        host_target(root, str(rustc), environment=command_environment)
        == toolchain["target"],
        "rustc target changed during performance evidence processing",
    )
    rustc_macos_deployment_target(
        root,
        rustc,
        toolchain["target"],
        environment=command_environment,
    )
    for name, path in paths.items():
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


def portable_reference_source_path(root: pathlib.Path) -> pathlib.Path:
    path = root.joinpath(*PORTABLE_REFERENCE_SOURCE_RELATIVE.parts)
    require(
        path.is_file() and not path.is_symlink(),
        "portable performance reference source is missing or unsafe",
    )
    return path.resolve()


def build_portable_reference_archive(
    root: pathlib.Path,
    target: str,
    clang: pathlib.Path,
    ar: pathlib.Path,
    output_dir: pathlib.Path,
    environment: dict[str, str],
) -> tuple[pathlib.Path, str, str]:
    """Build the private portable comparison object without changing product selection."""

    require(
        target == "aarch64-apple-darwin",
        "portable performance comparison requires aarch64-apple-darwin",
    )
    require_under(output_dir, root / "target", "portable reference build directory")
    source = portable_reference_source_path(root)
    source_digest = sha256_file(source)
    object_path = output_dir / f"{PORTABLE_REFERENCE_ARCHIVE_STEM}.o"
    archive_path = output_dir / f"lib{PORTABLE_REFERENCE_ARCHIVE_STEM}.a"
    include_root = root / "crates" / "q-periapt-mlkem-native-sys"
    sdk_root = environment.get("SDKROOT")
    require(
        isinstance(sdk_root, str) and bool(sdk_root),
        "portable performance reference build lacks SDKROOT",
    )
    command = [
        str(clang),
        "-c",
        str(source),
        "-o",
        str(object_path),
        "-Isrc",
        "-Ivendor/mlkem-native",
        "-isysroot",
        sdk_root,
        f"-std={C_LANGUAGE_STANDARD}",
        *MATCHED_C_CODEGEN_FLAGS,
        "-pedantic-errors",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wshadow",
        "-Wpointer-arith",
        "-Wmissing-prototypes",
        "-Wstrict-prototypes",
        "-Wundef",
        f"-fvisibility={C_VISIBILITY}",
        f"-march={PORTABLE_C_ARCHITECTURE}",
    ]
    for symbol in PORTABLE_REFERENCE_SYMBOLS:
        evidence_symbol = symbol.replace(
            "qpn_mlkem_bridge_",
            "qpn_mlkem_evidence_portable_",
            1,
        )
        command.append(f"-D{symbol}={evidence_symbol}")
    try:
        subprocess.run(
            command,
            cwd=include_root,
            env=environment,
            check=True,
        )
        subprocess.run(
            [str(ar), "rcs", str(archive_path), str(object_path)],
            cwd=include_root,
            env=environment,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"portable performance reference build failed: {exc}") from exc
    require(
        archive_path.is_file() and not archive_path.is_symlink(),
        "portable performance reference archive is missing or unsafe",
    )
    return archive_path.resolve(), sha256_file(archive_path), source_digest


def performance_harness_environment(
    environment: dict[str, str],
    *,
    target: str,
    portable_archive: pathlib.Path,
) -> dict[str, str]:
    """Add one private compile/link contract for the evidence-only reference."""

    require(
        target == "aarch64-apple-darwin",
        "implementation performance evidence requires aarch64-apple-darwin",
    )
    require(
        portable_archive.is_file() and not portable_archive.is_symlink(),
        "portable performance reference archive is missing or unsafe",
    )
    require(
        "CARGO_ENCODED_RUSTFLAGS" not in environment
        and "RUSTFLAGS" not in environment,
        "performance harness environment already contains Rust flags",
    )
    configured = dict(environment)
    configured["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        (
            "--cfg",
            "qperiapt_performance_evidence",
            "-L",
            f"native={portable_archive.parent}",
            "-l",
            f"static={PORTABLE_REFERENCE_ARCHIVE_STEM}",
        )
    )
    configured["QPERIAPT_PERFORMANCE_TARGET"] = target
    configured["QPERIAPT_PERFORMANCE_NATIVE_C_ARCHITECTURE"] = NATIVE_C_ARCHITECTURE
    configured["QPERIAPT_PERFORMANCE_PORTABLE_C_ARCHITECTURE"] = (
        PORTABLE_C_ARCHITECTURE
    )
    configured["QPERIAPT_PERFORMANCE_C_LANGUAGE_STANDARD"] = C_LANGUAGE_STANDARD
    configured["QPERIAPT_PERFORMANCE_C_OPTIMIZATION"] = C_OPTIMIZATION
    configured["QPERIAPT_PERFORMANCE_C_VISIBILITY"] = C_VISIBILITY
    configured["QPERIAPT_PERFORMANCE_MACOS_DEPLOYMENT_TARGET"] = (
        MACOS_DEPLOYMENT_TARGET
    )
    configured["QPERIAPT_PERFORMANCE_RUST_LTO"] = RUST_LTO
    configured["QPERIAPT_PERFORMANCE_RUST_OPTIMIZATION"] = RUST_OPTIMIZATION
    return configured


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


def publish_portable_reference_archive(
    root: pathlib.Path,
    target: str,
    archive: pathlib.Path,
    digest: str,
) -> pathlib.Path:
    destination = (
        root
        / "target"
        / "performance"
        / "binaries"
        / target
        / f"portable-reference-{digest}.a"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        require(
            not destination.is_symlink()
            and destination.is_file()
            and sha256_file(destination) == digest,
            "portable performance reference archive is unsafe or changed",
        )
        return destination.resolve()
    try:
        with archive.open("rb") as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        destination.chmod(0o600)
    except OSError as exc:
        raise GateError(
            f"cannot publish portable performance reference archive: {exc}"
        ) from exc
    require(
        sha256_file(destination) == digest,
        "published portable performance reference archive changed during copy",
    )
    return destination.resolve()


def hardened_cargo_environment(
    root: pathlib.Path,
    cargo: pathlib.Path,
    rustc: pathlib.Path,
    clang: pathlib.Path,
    ar: pathlib.Path,
    sdk: pathlib.Path,
    target: str,
    target_dir: pathlib.Path,
    private_root: pathlib.Path,
) -> dict[str, str]:
    home = account_home_directory()
    cargo_home = (home / ".cargo").resolve()
    require(cargo_home.is_dir(), f"Cargo home is missing: {cargo_home}")
    require(
        sdk.is_dir() and not sdk.is_symlink(),
        "performance macOS SDK is missing or unsafe",
    )
    try:
        resolved_sdk = sdk.resolve(strict=True)
    except OSError as exc:
        raise GateError(f"cannot resolve performance macOS SDK: {exc}") from exc
    require(resolved_sdk == sdk, "performance macOS SDK path is not canonical")
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
    target_cflags_key = "CFLAGS_" + re.sub(r"[^A-Za-z0-9]", "_", target)
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(private_home),
        "TMPDIR": str(private_tmp),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": str(RUST_CODEGEN_UNITS),
        "CARGO_PROFILE_RELEASE_LTO": RUST_LTO,
        "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
        "RUSTC": str(rustc),
        "CC": str(clang),
        "AR": str(ar),
        "SDKROOT": str(resolved_sdk),
        "MACOSX_DEPLOYMENT_TARGET": MACOS_DEPLOYMENT_TARGET,
        target_linker_key: str(clang),
        target_cflags_key: " ".join(MATCHED_C_CODEGEN_FLAGS),
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


def canonical_proof_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
    portable_archive: pathlib.Path,
    portable_archive_digest: str,
    portable_source_digest: str,
    toolchain: dict[str, str],
    raw_digest: str,
    budget_digest: str,
) -> dict[str, Any]:
    require(executable.is_file(), f"performance harness binary is missing: {executable}")
    require(sha256_file(executable) == binary_digest, "performance binary changed before proof emission")
    require(
        portable_archive.is_file() and not portable_archive.is_symlink(),
        "portable reference archive is missing or unsafe before proof emission",
    )
    require(
        sha256_file(portable_archive) == portable_archive_digest,
        "portable reference archive changed before proof emission",
    )
    portable_source = portable_reference_source_path(root)
    require(
        sha256_file(portable_source) == portable_source_digest,
        "portable reference source changed before proof emission",
    )
    validate_toolchain_identity(toolchain)
    build_contract = validate_build_contract(
        metadata.get("build_contract"), "proof build_contract"
    )
    payload = {
        "schema_version": PROOF_SCHEMA_VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "git_commit": git_commit(root),
        "source_tree_dirty": source_tree_dirty(root),
        "proof_source_tree_sha256": tree_digest,
        "environment": environment_observations,
        "toolchain": toolchain,
        "build_contract": build_contract,
        "harness": metadata,
        "artifacts": {
            "raw_path": relative_to_root(raw_path, root, "raw performance data"),
            "raw_sha256": raw_digest,
            "binary_path": relative_to_root(executable, root, "performance binary"),
            "binary_sha256": binary_digest,
            "portable_reference_archive_path": relative_to_root(
                portable_archive,
                root,
                "portable reference archive",
            ),
            "portable_reference_archive_sha256": portable_archive_digest,
            "portable_reference_source_path": PORTABLE_REFERENCE_SOURCE_RELATIVE.as_posix(),
            "portable_reference_source_sha256": portable_source_digest,
            "budget_path": PRODUCTION_BUDGET_RELATIVE.as_posix(),
            "budget_sha256": budget_digest,
        },
        "analysis": analysis,
        "gate": {"passed": True},
    }
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    proof_path.write_bytes(canonical_proof_bytes(payload))
    return payload


def verify_emitted_collection(
    root: pathlib.Path,
    *,
    allow_dirty: bool,
    tree_digest: str,
    raw_path: pathlib.Path,
    raw_snapshot: FileSnapshot,
    proof_path: pathlib.Path,
    proof_payload: dict[str, Any],
    evidence_binary: pathlib.Path,
    binary_digest: str,
    evidence_portable_archive: pathlib.Path,
    portable_archive_digest: str,
    portable_source_digest: str,
    budget_path: pathlib.Path,
    budget_snapshot: JsonObjectSnapshot,
    toolchain: dict[str, str],
    cargo: pathlib.Path,
    rustc: pathlib.Path,
    clang: pathlib.Path,
    ar: pathlib.Path,
) -> None:
    """Re-sample every emitted input immediately before collector success."""

    try:
        final_raw = read_regular_snapshot(
            raw_path,
            maximum=MAX_PERFORMANCE_RAW_BYTES,
            label="emitted raw performance data",
        )
        final_binary = read_regular_snapshot(
            evidence_binary,
            maximum=MAX_PERFORMANCE_RAW_BYTES,
            label="emitted performance binary",
        )
        final_archive = read_regular_snapshot(
            evidence_portable_archive,
            maximum=MAX_PERFORMANCE_RAW_BYTES,
            label="emitted portable reference archive",
        )
        final_portable_source = read_regular_snapshot(
            portable_reference_source_path(root),
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="portable reference source",
        )
        final_budget = load_json_object_snapshot(
            budget_path,
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="emitted performance budget",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc

    require(
        final_raw.sha256 == raw_snapshot.sha256
        and final_raw.data == raw_snapshot.data,
        "raw performance data changed during proof emission",
    )
    require(
        final_binary.sha256 == binary_digest,
        "performance binary changed during proof emission",
    )
    require(
        final_archive.sha256 == portable_archive_digest,
        "portable reference archive changed during proof emission",
    )
    require(
        final_portable_source.sha256 == portable_source_digest,
        "portable reference source changed during proof emission",
    )
    require(
        final_budget.file.sha256 == budget_snapshot.file.sha256
        and final_budget.file.data == budget_snapshot.file.data
        and final_budget.value == budget_snapshot.value,
        "performance budget changed during proof emission",
    )
    require(
        source_tree_digest(root) == tree_digest,
        "source tree changed during performance proof emission",
    )
    if not allow_dirty:
        require(
            not source_tree_dirty(root),
            "source tree became dirty during performance proof emission",
        )
    require_toolchain_unchanged(root, toolchain, cargo, rustc, clang, ar)

    expected_proof = canonical_proof_bytes(proof_payload)
    expected_proof_digest = hashlib.sha256(expected_proof).hexdigest()
    try:
        final_proof = load_json_object_snapshot(
            proof_path,
            maximum=MAX_PERFORMANCE_PROOF_BYTES,
            label="emitted performance proof",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    require(
        final_proof.file.sha256 == expected_proof_digest,
        "performance proof changed during proof emission",
    )
    require(
        final_proof.file.data == expected_proof
        and final_proof.value == proof_payload,
        "performance proof content changed during proof emission",
    )


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
    samples, warmup_ms = collection_parameters_from_budget(budget_snapshot.value)
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
    toolchain, cargo, rustc, clang, ar = verified_toolchain(
        root, budget_snapshot.value
    )
    require_toolchain_unchanged(root, toolchain, cargo, rustc, clang, ar)
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
            root,
            cargo,
            rustc,
            clang,
            ar,
            pathlib.Path(toolchain["sdk_path"]),
            target,
            target_dir,
            private_root,
        )
        portable_build_dir = private_root / "portable-reference"
        portable_build_dir.mkdir(mode=0o700)
        (
            portable_archive,
            portable_archive_digest,
            portable_source_digest,
        ) = build_portable_reference_archive(
            root,
            target,
            clang,
            ar,
            portable_build_dir,
            env,
        )
        harness_env = performance_harness_environment(
            env,
            target=target,
            portable_archive=portable_archive,
        )
        executable, binary_digest = build_harness(
            root, target, cargo, target_dir, harness_env
        )
        require_distinct_paths(
            {
                "raw performance data": raw_path,
                "performance proof": proof_path,
                "performance binary": executable,
                "portable reference archive": portable_archive,
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
            str(samples),
            "--warmup-ms",
            str(warmup_ms),
            "--raw-out",
            str(raw_path),
        ]
        try:
            subprocess.run(command, cwd=root, env=harness_env, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise GateError(f"performance harness failed: {exc}") from exc
        environment_observations["post_run"] = collect_environment()
        verify_environment(
            environment_observations["post_run"], args.allow_uncontrolled
        )
        require(sha256_file(executable) == binary_digest, "performance binary changed during collection")
        require(
            sha256_file(portable_archive) == portable_archive_digest,
            "portable reference archive changed during collection",
        )
        after_run = source_tree_digest(root)
        require(before == after_run, f"source tree changed during performance collection: {before} != {after_run}")
        raw_snapshot, metadata, grouped = parse_raw_snapshot(raw_path)
        analysis = analyse(metadata, grouped, budget_snapshot.value)
        environment_observations["post_analysis"] = collect_environment()
        verify_environment_observations(
            environment_observations, args.allow_uncontrolled
        )
        require_toolchain_unchanged(root, toolchain, cargo, rustc, clang, ar)
        before_emit = source_tree_digest(root)
        require(before == before_emit, f"source tree changed before performance proof emission: {before} != {before_emit}")
        evidence_binary = publish_performance_binary(
            root, target, executable, binary_digest
        )
        evidence_portable_archive = publish_portable_reference_archive(
            root,
            target,
            portable_archive,
            portable_archive_digest,
        )
        proof_payload = emit_proof(
            root,
            raw_path,
            proof_path,
            metadata,
            analysis,
            environment_observations,
            before,
            evidence_binary,
            binary_digest,
            evidence_portable_archive,
            portable_archive_digest,
            portable_source_digest,
            toolchain,
            raw_snapshot.sha256,
            budget_snapshot.file.sha256,
        )
    verify_emitted_collection(
        root,
        allow_dirty=args.allow_dirty,
        tree_digest=before,
        raw_path=raw_path,
        raw_snapshot=raw_snapshot,
        proof_path=proof_path,
        proof_payload=proof_payload,
        evidence_binary=evidence_binary,
        binary_digest=binary_digest,
        evidence_portable_archive=evidence_portable_archive,
        portable_archive_digest=portable_archive_digest,
        portable_source_digest=portable_source_digest,
        budget_path=budget_path,
        budget_snapshot=budget_snapshot,
        toolchain=toolchain,
        cargo=cargo,
        rustc=rustc,
        clang=clang,
        ar=ar,
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
            "build_contract",
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
    proof_build_contract = validate_build_contract(
        proof.get("build_contract"), "performance proof build_contract"
    )
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
    toolchain = validate_toolchain_identity(proof.get("toolchain"))
    try:
        current_budget = load_json_object_snapshot(
            production_budget_path(root),
            maximum=MAX_PERFORMANCE_BUDGET_BYTES,
            label="production performance budget",
        )
    except EvidenceIOError as exc:
        raise GateError(str(exc)) from exc
    current_toolchain, _cargo, _rustc, _clang, _ar = verified_toolchain(
        root, current_budget.value
    )
    require(toolchain == current_toolchain, "performance proof toolchain differs from current policy-bound toolchain")
    require_toolchain_unchanged(
        root, current_toolchain, _cargo, _rustc, _clang, _ar
    )
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
        {
            "binary_path",
            "binary_sha256",
            "budget_path",
            "budget_sha256",
            "portable_reference_archive_path",
            "portable_reference_archive_sha256",
            "portable_reference_source_path",
            "portable_reference_source_sha256",
            "raw_path",
            "raw_sha256",
        },
        "performance artifacts",
    )
    raw_path = proof_artifact_path(root, artifacts.get("raw_path"), "raw performance data")
    executable = proof_artifact_path(root, artifacts.get("binary_path"), "performance binary")
    portable_archive = proof_artifact_path(
        root,
        artifacts.get("portable_reference_archive_path"),
        "portable reference archive",
    )
    budget_path = production_budget_path(root)
    require_distinct_paths(
        {
            "performance proof": proof_path,
            "raw performance data": raw_path,
            "performance binary": executable,
            "portable reference archive": portable_archive,
            "performance budget": budget_path,
        }
    )
    raw_expected = artifacts.get("raw_sha256")
    binary_expected = artifacts.get("binary_sha256")
    portable_archive_expected = artifacts.get(
        "portable_reference_archive_sha256"
    )
    portable_source_expected = artifacts.get("portable_reference_source_sha256")
    for field, expected in (
        ("raw_sha256", raw_expected),
        ("binary_sha256", binary_expected),
        ("portable_reference_archive_sha256", portable_archive_expected),
        ("portable_reference_source_sha256", portable_source_expected),
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
    require(
        portable_archive.parent
        == (root / "target" / "performance" / "binaries" / target).resolve()
        and portable_archive.name
        == f"portable-reference-{portable_archive_expected}.a",
        "performance proof names an unexpected portable reference archive path",
    )
    require(
        artifacts.get("portable_reference_source_path")
        == PORTABLE_REFERENCE_SOURCE_RELATIVE.as_posix(),
        "performance proof names an unexpected portable reference source path",
    )
    portable_source = portable_reference_source_path(root)
    raw_snapshot, metadata, grouped = parse_raw_snapshot(raw_path)
    require(raw_snapshot.sha256 == raw_expected, f"performance artifact changed: {raw_path}")
    require(binary_expected == sha256_file(executable), f"performance artifact changed: {executable}")
    require(
        portable_archive_expected == sha256_file(portable_archive),
        f"performance artifact changed: {portable_archive}",
    )
    require(
        portable_source_expected == sha256_file(portable_source),
        f"performance artifact changed: {portable_source}",
    )
    budget_snapshot = verified_production_budget_snapshot(root, artifacts)
    require(
        budget_snapshot.file.sha256 == current_budget.file.sha256,
        "performance budget changed during verification",
    )
    analysis = analyse(metadata, grouped, budget_snapshot.value)
    require(
        proof_build_contract == metadata.get("build_contract")
        and proof_build_contract == budget_snapshot.value.get("build_contract"),
        "performance proof build contract differs from raw data or budget",
    )
    require(proof.get("harness") == metadata, "performance proof harness metadata changed")
    require(proof.get("analysis") == analysis, "performance proof analysis changed")
    require(proof.get("gate") == {"passed": True}, "performance proof is not a passing gate")
    require(expected_tree == source_tree_digest(root), "source tree changed during performance verification")
    if not args.allow_dirty:
        require(not source_tree_dirty(root), "source tree became dirty during performance verification")
    require_toolchain_unchanged(
        root, current_toolchain, _cargo, _rustc, _clang, _ar
    )
    require(raw_expected == sha256_file(raw_path), "raw performance data changed during verification")
    require(binary_expected == sha256_file(executable), "performance binary changed during verification")
    require(
        portable_archive_expected == sha256_file(portable_archive),
        "portable reference archive changed during verification",
    )
    require(
        portable_source_expected == sha256_file(portable_source),
        "portable reference source changed during verification",
    )
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
        "PERFORMANCE_RAW_SCHEMA_PASS "
        f"mode={metadata['mode']} "
        f"samples={metadata['samples_per_variant_operation']} "
        f"raw={args.raw.resolve()}"
    )


def positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"must be an integer: {raw}") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError(f"must be positive: {raw}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--root", type=pathlib.Path, required=True)
    collect_parser.add_argument("--raw", type=pathlib.Path, required=True)
    collect_parser.add_argument("--proof", type=pathlib.Path, required=True)
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
