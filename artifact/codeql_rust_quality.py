#!/usr/bin/env python3
"""Fail-closed quality gate for the same-run Rust CodeQL database."""

from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence

from bounded_process import BoundedProcessError, capture_stdout
from evidence_io import EvidenceIOError, parse_strict_json_bytes
from git_provenance import GitProvenanceError, inspect_worktree, run_git_bytes


ARTIFACT_DIR = pathlib.Path(__file__).resolve(strict=True).parent
REPOSITORY_ROOT = ARTIFACT_DIR.parent
QUERY_DIR = ARTIFACT_DIR / "codeql-rust-quality"
EXTRACTED_PATHS_QUERY = QUERY_DIR / "ExtractedPaths.ql"
METRICS_QUERY = QUERY_DIR / "Metrics.ql"
UNRESOLVED_MACROS_QUERY = QUERY_DIR / "UnresolvedMacros.ql"
EXPECTED_TRACKED_RUST_SOURCE_COUNT = 87
CODEQL_COMMAND_TIMEOUT_SECONDS = 300
MAX_CODEQL_QUERY_DIAGNOSTIC_BYTES = 4 * 1024 * 1024
MAX_CODEQL_DECODED_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_METRICS = frozenset(
    {
        "extraction_errors",
        "extraction_warnings",
        "extracted_files",
        "successfully_extracted_files",
        "unextracted_elements",
        "source_macro_calls",
        "unresolved_source_macro_calls",
        "source_format_args",
        "source_format_args_without_expr",
        "source_format_args_without_dataflow_node",
        "ast_inconsistencies",
        "path_resolution_inconsistencies",
        "path_multiple_path_resolutions",
        "path_multiple_resolved_targets",
        "path_multiple_record_fields",
        "path_multiple_tuple_fields",
        "path_multiple_canonical_paths",
        "type_inference_inconsistencies",
        "type_missing_parameter_id",
        "type_nonfunctional_parameter_id",
        "type_noninjective_parameter_id",
        "type_ill_formed_mention",
        "type_nonunique_certain_information",
        "cfg_inconsistencies",
        "ssa_inconsistencies",
        "dataflow_inconsistencies",
    }
)
TELEMETRY_METRICS = frozenset(
    {
        "path_resolution_inconsistencies",
        "path_multiple_path_resolutions",
        "path_multiple_resolved_targets",
        "path_multiple_record_fields",
        "path_multiple_tuple_fields",
        "path_multiple_canonical_paths",
        "type_inference_inconsistencies",
        "type_missing_parameter_id",
        "type_nonfunctional_parameter_id",
        "type_noninjective_parameter_id",
        "type_ill_formed_mention",
        "type_nonunique_certain_information",
    }
)
ZERO_METRICS = EXPECTED_METRICS - TELEMETRY_METRICS - {
    "extracted_files",
    "successfully_extracted_files",
    "source_macro_calls",
    "source_format_args",
}


class CodeQLRustQualityError(ValueError):
    """The CodeQL database cannot support a complete Rust analysis claim."""


def _decode_nul_paths(raw: bytes) -> tuple[str, ...]:
    records = raw.split(b"\0")
    if records[-1] != b"":
        raise CodeQLRustQualityError("git path inventory is not NUL terminated")
    paths: list[str] = []
    for record in records[:-1]:
        try:
            path = record.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CodeQLRustQualityError("tracked path is not UTF-8") from exc
        pure = pathlib.PurePosixPath(path)
        if (
            not path
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
        ):
            raise CodeQLRustQualityError(f"tracked path is not canonical: {path!r}")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise CodeQLRustQualityError("tracked path inventory contains duplicates")
    return tuple(paths)


def tracked_rust_paths(root: pathlib.Path = REPOSITORY_ROOT) -> frozenset[str]:
    try:
        tracked = _decode_nul_paths(
            run_git_bytes(root, ["ls-files", "--cached", "-z", "--", "*.rs"])
        )
    except GitProvenanceError as exc:
        raise CodeQLRustQualityError(f"cannot inventory tracked Rust sources: {exc}") from exc
    rust_paths = frozenset(tracked)
    if any(not path.endswith(".rs") for path in rust_paths):
        raise CodeQLRustQualityError("tracked Rust source query returned a non-Rust path")
    if len(rust_paths) != EXPECTED_TRACKED_RUST_SOURCE_COUNT:
        raise CodeQLRustQualityError(
            "tracked Rust source count must be "
            f"{EXPECTED_TRACKED_RUST_SOURCE_COUNT}, got {len(rust_paths)}"
        )
    return rust_paths


def require_clean_checkout(expected_commit: str) -> None:
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
    except GitProvenanceError as exc:
        raise CodeQLRustQualityError(f"cannot inspect checkout provenance: {exc}") from exc
    if inspection.commit != expected_commit:
        raise CodeQLRustQualityError(
            f"checkout commit {inspection.commit} does not match {expected_commit}"
        )
    if inspection.dirty:
        raise CodeQLRustQualityError(
            "checkout changed during Rust CodeQL analysis: "
            + "; ".join(inspection.reasons[:8])
        )


def require_repository_target_absent(
    root: pathlib.Path = REPOSITORY_ROOT,
) -> None:
    if os.path.lexists(root / "target"):
        raise CodeQLRustQualityError(
            "repository-local target must be absent during Rust CodeQL analysis"
        )


def _require_absolute_regular_file(raw: str, label: str) -> pathlib.Path:
    candidate = pathlib.Path(raw)
    if not candidate.is_absolute():
        raise CodeQLRustQualityError(f"{label} must be an absolute path")
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except OSError as exc:
        raise CodeQLRustQualityError(f"{label} is unavailable: {candidate}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(resolved_metadata.st_mode):
        raise CodeQLRustQualityError(f"{label} must be a non-symlink regular file: {candidate}")
    if not os.access(resolved, os.X_OK):
        raise CodeQLRustQualityError(f"{label} is not executable: {resolved}")
    return resolved


def _require_database(raw_locations: str, runner_temp: pathlib.Path) -> pathlib.Path:
    try:
        locations = parse_strict_json_bytes(
            raw_locations.encode("utf-8"),
            label="CodeQL database locations output",
        )
    except (EvidenceIOError, UnicodeEncodeError) as exc:
        raise CodeQLRustQualityError(
            "CodeQL database locations output is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(locations, dict) or set(locations) != {"rust"}:
        raise CodeQLRustQualityError(
            "CodeQL database locations must contain exactly the rust database"
        )
    raw_database = locations["rust"]
    if not isinstance(raw_database, str) or not raw_database:
        raise CodeQLRustQualityError("Rust CodeQL database location is malformed")
    candidate = pathlib.Path(raw_database)
    if not candidate.is_absolute():
        raise CodeQLRustQualityError("Rust CodeQL database location must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(runner_temp)
    except (OSError, ValueError) as exc:
        raise CodeQLRustQualityError(
            "Rust CodeQL database must be a real directory under the runner temp root"
        ) from exc
    if resolved != candidate or not resolved.is_dir():
        raise CodeQLRustQualityError(
            "Rust CodeQL database must be a non-symlink directory"
        )
    metadata = resolved / "codeql-database.yml"
    if not metadata.is_file() or metadata.is_symlink():
        raise CodeQLRustQualityError(
            f"Rust CodeQL database metadata is unavailable: {metadata}"
        )
    return resolved


def _require_runner_temp(raw: str) -> pathlib.Path:
    candidate = pathlib.Path(raw)
    if not candidate.is_absolute():
        raise CodeQLRustQualityError("runner temp root must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CodeQLRustQualityError(f"runner temp root is unavailable: {exc}") from exc
    if resolved != candidate or not resolved.is_dir():
        raise CodeQLRustQualityError("runner temp root must be a non-symlink directory")
    return resolved


def _run_query(
    codeql: pathlib.Path,
    database: pathlib.Path,
    query: pathlib.Path,
    output: pathlib.Path,
) -> None:
    try:
        result = capture_stdout(
            [
                str(codeql),
                "query",
                "run",
                "--warnings=error",
                f"--database={database}",
                f"--output={output}",
                str(query),
            ],
            timeout_seconds=CODEQL_COMMAND_TIMEOUT_SECONDS,
            maximum_bytes=MAX_CODEQL_QUERY_DIAGNOSTIC_BYTES,
            stderr=subprocess.STDOUT,
        )
    except BoundedProcessError as exc:
        raise CodeQLRustQualityError(
            f"CodeQL quality query {query.name} failed at {exc.kind} boundary: {exc}"
        ) from exc
    try:
        diagnostics = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodeQLRustQualityError(
            f"CodeQL quality query {query.name} emitted non-UTF-8 diagnostics"
        ) from exc
    if diagnostics:
        sys.stdout.write(diagnostics)
        sys.stdout.flush()
    if result.returncode != 0:
        raise CodeQLRustQualityError(
            f"CodeQL quality query {query.name} exited with status {result.returncode}"
        )


def _decode_query(codeql: pathlib.Path, bqrs: pathlib.Path) -> list[list[object]]:
    try:
        result = capture_stdout(
            [str(codeql), "bqrs", "decode", "--format=json", str(bqrs)],
            timeout_seconds=CODEQL_COMMAND_TIMEOUT_SECONDS,
            maximum_bytes=MAX_CODEQL_DECODED_JSON_BYTES,
            stderr=subprocess.STDOUT,
        )
    except BoundedProcessError as exc:
        raise CodeQLRustQualityError(
            f"CodeQL query decoder failed at {exc.kind} boundary: {exc}"
        ) from exc
    if result.returncode != 0:
        raise CodeQLRustQualityError(
            f"CodeQL query decoder exited with status {result.returncode}"
        )
    try:
        decoded = parse_strict_json_bytes(
            result.stdout,
            label="CodeQL query result",
        )
    except EvidenceIOError as exc:
        raise CodeQLRustQualityError(
            "CodeQL query result is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(decoded, dict) or set(decoded) != {"#select"}:
        raise CodeQLRustQualityError("CodeQL query result has an unexpected result set")
    selected = decoded["#select"]
    if not isinstance(selected, dict) or not isinstance(selected.get("tuples"), list):
        raise CodeQLRustQualityError("CodeQL query result has no tuple list")
    tuples = selected["tuples"]
    if not all(isinstance(row, list) for row in tuples):
        raise CodeQLRustQualityError("CodeQL query result contains a malformed tuple")
    return tuples


def _parse_extracted_paths(rows: Sequence[Sequence[object]]) -> frozenset[str]:
    extracted: list[str] = []
    for row in rows:
        if len(row) != 1 or not isinstance(row[0], str):
            raise CodeQLRustQualityError("extracted-path query returned a malformed row")
        path = row[0]
        pure = pathlib.PurePosixPath(path)
        if (
            not path
            or not path.endswith(".rs")
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
        ):
            raise CodeQLRustQualityError(f"extracted Rust path is not canonical: {path!r}")
        extracted.append(path)
    if len(extracted) != len(set(extracted)):
        raise CodeQLRustQualityError("extracted Rust path query contains duplicates")
    return frozenset(extracted)


def _parse_metrics(rows: Sequence[Sequence[object]]) -> dict[str, int]:
    metrics: dict[str, int] = {}
    for row in rows:
        if (
            len(row) != 2
            or not isinstance(row[0], str)
            or not isinstance(row[1], int)
            or isinstance(row[1], bool)
            or row[1] < 0
        ):
            raise CodeQLRustQualityError("metrics query returned a malformed row")
        name, value = row
        if name in metrics:
            raise CodeQLRustQualityError(f"metrics query duplicated {name}")
        metrics[name] = value
    if set(metrics) != EXPECTED_METRICS:
        missing = sorted(EXPECTED_METRICS - set(metrics))
        unexpected = sorted(set(metrics) - EXPECTED_METRICS)
        raise CodeQLRustQualityError(
            f"metrics query key mismatch; missing={missing}, unexpected={unexpected}"
        )
    return metrics


def _parse_unresolved_macros(
    rows: Sequence[Sequence[object]],
) -> list[list[object]]:
    details: list[list[object]] = []
    for row in rows:
        if (
            len(row) != 4
            or not isinstance(row[0], str)
            or not isinstance(row[1], int)
            or isinstance(row[1], bool)
            or row[1] <= 0
            or not isinstance(row[2], int)
            or isinstance(row[2], bool)
            or row[2] <= 0
            or not isinstance(row[3], str)
            or not row[3]
        ):
            raise CodeQLRustQualityError(
                "unresolved macro query returned a malformed row"
            )
        path = row[0]
        pure = pathlib.PurePosixPath(path)
        if (
            not path.endswith(".rs")
            or pure.is_absolute()
            or ".." in pure.parts
            or pure.as_posix() != path
        ):
            raise CodeQLRustQualityError(
                f"unresolved macro path is not canonical: {path!r}"
            )
        details.append(list(row))
    if len(details) != len({tuple(detail) for detail in details}):
        raise CodeQLRustQualityError(
            "unresolved macro query returned duplicate detail rows"
        )
    return sorted(
        details,
        key=lambda detail: (detail[0], detail[1], detail[2], detail[3]),
    )


def validate_unresolved_detail_count(metric: int, details: Sequence[object]) -> None:
    if len(details) != metric:
        raise CodeQLRustQualityError(
            "unresolved macro detail count differs from its metric"
        )


def validate_quality(
    tracked: frozenset[str],
    extracted: frozenset[str],
    metrics: Mapping[str, int],
) -> None:
    if extracted != tracked:
        missing = sorted(tracked - extracted)
        unexpected = sorted(extracted - tracked)
        raise CodeQLRustQualityError(
            "CodeQL successfully extracted path set differs from tracked Rust sources; "
            f"missing={missing[:8]}, unexpected={unexpected[:8]}"
        )
    expected_count = len(tracked)
    for name in ("extracted_files", "successfully_extracted_files"):
        if metrics[name] != expected_count:
            raise CodeQLRustQualityError(
                f"{name} must equal tracked Rust source count {expected_count}, "
                f"got {metrics[name]}"
            )
    for name in sorted(ZERO_METRICS):
        if metrics[name] != 0:
            raise CodeQLRustQualityError(f"{name} must be zero, got {metrics[name]}")
    for name in ("source_macro_calls", "source_format_args"):
        if metrics[name] <= 0:
            raise CodeQLRustQualityError(f"{name} sentinel must be nonzero")
    path_total = sum(
        metrics[name]
        for name in TELEMETRY_METRICS
        if name.startswith("path_") and name != "path_resolution_inconsistencies"
    )
    if path_total != metrics["path_resolution_inconsistencies"]:
        raise CodeQLRustQualityError("path inconsistency categories do not sum to total")
    type_total = sum(
        metrics[name]
        for name in TELEMETRY_METRICS
        if name.startswith("type_") and name != "type_inference_inconsistencies"
    )
    if type_total != metrics["type_inference_inconsistencies"]:
        raise CodeQLRustQualityError("type inconsistency categories do not sum to total")


def main() -> None:
    try:
        require_repository_target_absent()
        expected_commit = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
        if not expected_commit:
            raise CodeQLRustQualityError("expected checkout commit is missing")
        require_clean_checkout(expected_commit)
        runner_temp = _require_runner_temp(os.environ.get("CODEQL_RUNNER_TEMP", ""))
        codeql = _require_absolute_regular_file(
            os.environ.get("CODEQL_BINARY", ""), "CodeQL binary"
        )
        database = _require_database(
            os.environ.get("CODEQL_DATABASE_LOCATIONS", ""), runner_temp
        )
        tracked = tracked_rust_paths()
        with tempfile.TemporaryDirectory(
            prefix="qperiapt-codeql-quality.", dir=runner_temp
        ) as temporary:
            output_dir = pathlib.Path(temporary)
            paths_bqrs = output_dir / "extracted-paths.bqrs"
            metrics_bqrs = output_dir / "metrics.bqrs"
            unresolved_bqrs = output_dir / "unresolved-macros.bqrs"
            _run_query(codeql, database, EXTRACTED_PATHS_QUERY, paths_bqrs)
            _run_query(codeql, database, METRICS_QUERY, metrics_bqrs)
            _run_query(codeql, database, UNRESOLVED_MACROS_QUERY, unresolved_bqrs)
            extracted = _parse_extracted_paths(_decode_query(codeql, paths_bqrs))
            metrics = _parse_metrics(_decode_query(codeql, metrics_bqrs))
            unresolved = _parse_unresolved_macros(
                _decode_query(codeql, unresolved_bqrs)
            )
            unresolved_metric = metrics["unresolved_source_macro_calls"]
            validate_unresolved_detail_count(unresolved_metric, unresolved)
            if unresolved:
                print(
                    "CODEQL_RUST_UNRESOLVED_MACROS "
                    + json.dumps(unresolved, ensure_ascii=True, separators=(",", ":"))
                )
        validate_quality(tracked, extracted, metrics)
        require_repository_target_absent()
        require_clean_checkout(expected_commit)
    except CodeQLRustQualityError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(
        "CODEQL_RUST_INTERNAL_CONSISTENCY_TELEMETRY "
        + json.dumps(
            {name: metrics[name] for name in sorted(TELEMETRY_METRICS)},
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    print(
        "CODEQL_RUST_DATABASE_QUALITY_PASS "
        f"tracked_rs={len(tracked)} "
        f"source_macro_calls={metrics['source_macro_calls']} "
        f"source_format_args={metrics['source_format_args']}"
    )


if __name__ == "__main__":
    main()
