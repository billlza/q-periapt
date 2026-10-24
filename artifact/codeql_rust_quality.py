#!/usr/bin/env python3
"""Fail-closed quality gate for the same-run Rust CodeQL database."""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence

from bounded_process import BoundedProcessError, TimeoutPolicy, capture_stdout
from evidence_io import EvidenceIOError, parse_strict_json_bytes
from git_provenance import GitProvenanceError, inspect_worktree, run_git_bytes


ARTIFACT_DIR = pathlib.Path(__file__).resolve(strict=True).parent
REPOSITORY_ROOT = ARTIFACT_DIR.parent
QUERY_DIR = ARTIFACT_DIR / "codeql-rust-quality"
EXTRACTED_PATHS_QUERY = QUERY_DIR / "ExtractedPaths.ql"
METRICS_QUERY = QUERY_DIR / "Metrics.ql"
UNRESOLVED_MACROS_QUERY = QUERY_DIR / "UnresolvedMacros.ql"
FIXED_CODEQL_BINARY = pathlib.Path(
    "/opt/hostedtoolcache/CodeQL/2.27.2/x64/codeql/codeql"
)
FIXED_CODEQL_DATABASE = pathlib.Path(
    "/home/runner/work/_temp/qperiapt-codeql-database/rust"
)
FIXED_RUNNER_TEMP = pathlib.Path("/home/runner/work/_temp")
# Exact tracked Rust inventory, including native, C and browser lifecycle sources.
EXPECTED_TRACKED_RUST_SOURCE_COUNT = 983
CODEQL_COMMAND_TIMEOUT_SECONDS = 300
# The whole-program Metrics query exceeded 900 seconds on hosted Apple Silicon;
# its frozen database completed locally in 670 seconds with the same 2-thread,
# 5500-MB budget. Keep the extended deadline finite and lighter queries unchanged.
CODEQL_METRICS_TIMEOUT_SECONDS = 1800
CODEQL_QUERY_THREADS = 4
CODEQL_QUERY_RAM_MB = 14_000
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


@dataclasses.dataclass(frozen=True)
class HostedConfiguration:
    platform: str
    compiler_host: str
    codeql: pathlib.Path
    database: pathlib.Path
    runner_temp: pathlib.Path
    threads: int
    ram_mb: int


def hosted_configuration(host: str) -> HostedConfiguration:
    """Select reviewed hosted paths and budgets; never accept environment paths."""
    if host == "linux":
        return HostedConfiguration(host, "x86_64-unknown-linux-gnu", FIXED_CODEQL_BINARY,
                                   FIXED_CODEQL_DATABASE, FIXED_RUNNER_TEMP,
                                   CODEQL_QUERY_THREADS, CODEQL_QUERY_RAM_MB)
    if host == "darwin":
        temporary = pathlib.Path("/Users/runner/work/_temp")
        return HostedConfiguration(
            host, "aarch64-apple-darwin",
            pathlib.Path("/Users/runner/hostedtoolcache/CodeQL/2.27.2/arm64/codeql/codeql"),
            temporary / "qperiapt-codeql-database/rust", temporary, 2, 5500,
        )
    raise CodeQLRustQualityError("unsupported hosted Rust analysis platform")


def _merge_cleanup_failure(primary: BaseException, message: str) -> None:
    """Preserve control exceptions; otherwise expose cleanup in the domain error."""

    if not isinstance(primary, Exception):
        primary.add_note(message)
        return
    raise CodeQLRustQualityError(f"{primary}; {message}") from primary


def _close_binding_descriptors(
    descriptors: Sequence[tuple[int, str]],
) -> None:
    failures: list[str] = []
    control_failure: BaseException | None = None
    for descriptor, label in descriptors:
        if descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except BaseException as exc:
            message = f"close CodeQL {label} binding: {exc}"
            if not isinstance(exc, Exception) and control_failure is None:
                control_failure = exc
            else:
                failures.append(message)
    if control_failure is not None:
        if failures:
            control_failure.add_note("; ".join(failures))
        raise control_failure
    if failures:
        raise CodeQLRustQualityError("; ".join(failures))


@dataclasses.dataclass(frozen=True)
class _PathIdentity:
    device: int
    inode: int


@dataclasses.dataclass(frozen=True)
class _FixedCodeQLPathBindings:
    codeql: pathlib.Path
    database: pathlib.Path
    runner_temp: pathlib.Path
    codeql_descriptor: int
    database_descriptor: int
    database_metadata_descriptor: int
    runner_temp_descriptor: int
    codeql_identity: _PathIdentity
    database_identity: _PathIdentity
    database_metadata_identity: _PathIdentity
    runner_temp_identity: _PathIdentity
    threads: int = CODEQL_QUERY_THREADS
    ram_mb: int = CODEQL_QUERY_RAM_MB


def _identity(metadata: os.stat_result) -> _PathIdentity:
    return _PathIdentity(device=metadata.st_dev, inode=metadata.st_ino)


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_open_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


def _canonical_fixed_metadata(path: pathlib.Path, label: str) -> os.stat_result:
    if not isinstance(path, pathlib.Path) or not path.is_absolute():
        raise CodeQLRustQualityError(f"{label} must be one fixed absolute path")
    try:
        metadata = os.lstat(path)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CodeQLRustQualityError(f"{label} is unavailable: {path}: {exc}") from exc
    if resolved != path or stat.S_ISLNK(metadata.st_mode):
        raise CodeQLRustQualityError(
            f"{label} must be canonical and contain no symlink components"
        )
    return metadata


def _require_codeql_metadata(metadata: os.stat_result) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if not stat.S_ISREG(metadata.st_mode):
        raise CodeQLRustQualityError(
            "fixed CodeQL binary must be a regular file"
        )
    if not mode & 0o111:
        raise CodeQLRustQualityError(
            "fixed CodeQL binary must be executable"
        )


def _require_owned_directory_metadata(
    metadata: os.stat_result, label: str
) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CodeQLRustQualityError(
            f"{label} must be a current-user-owned directory without group or "
            "other write permission"
        )


def _require_database_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise CodeQLRustQualityError(
            "Rust CodeQL database metadata must be one current-user-owned, "
            "not-group-or-other-writable regular file with one link"
        )


def _open_fixed_codeql_bindings(*, host: str = "linux") -> _FixedCodeQLPathBindings:
    configuration = hosted_configuration(host)
    if sys.platform != configuration.platform:
        raise CodeQLRustQualityError(
            "fixed Rust CodeQL path bindings require the selected analysis platform"
        )
    codeql = configuration.codeql
    database = configuration.database
    runner_temp = configuration.runner_temp
    codeql_path_metadata = _canonical_fixed_metadata(
        codeql, "fixed CodeQL binary"
    )
    database_path_metadata = _canonical_fixed_metadata(
        database, "fixed Rust CodeQL database"
    )
    runner_temp_path_metadata = _canonical_fixed_metadata(
        runner_temp, "fixed CodeQL temporary parent"
    )
    try:
        database.relative_to(runner_temp)
    except ValueError as exc:
        raise CodeQLRustQualityError(
            "fixed Rust CodeQL database must be under the fixed temporary parent"
        ) from exc
    codeql_descriptor = -1
    database_descriptor = -1
    database_metadata_descriptor = -1
    runner_temp_descriptor = -1
    try:
        codeql_descriptor = os.open(codeql, _file_open_flags())
        codeql_metadata = os.fstat(codeql_descriptor)
        _require_codeql_metadata(codeql_metadata)
        if _identity(codeql_metadata) != _identity(codeql_path_metadata):
            raise CodeQLRustQualityError(
                "fixed CodeQL binary changed while it was being opened"
            )

        database_descriptor = os.open(
            database, _directory_open_flags()
        )
        database_metadata = os.fstat(database_descriptor)
        _require_owned_directory_metadata(
            database_metadata, "fixed Rust CodeQL database"
        )
        if _identity(database_metadata) != _identity(database_path_metadata):
            raise CodeQLRustQualityError(
                "fixed Rust CodeQL database changed while it was being opened"
            )
        database_metadata_descriptor = os.open(
            "codeql-database.yml",
            _file_open_flags(),
            dir_fd=database_descriptor,
        )
        database_file_metadata = os.fstat(database_metadata_descriptor)
        _require_database_metadata(database_file_metadata)
        database_file_path_metadata = os.stat(
            "codeql-database.yml",
            dir_fd=database_descriptor,
            follow_symlinks=False,
        )
        _require_database_metadata(database_file_path_metadata)
        if _identity(database_file_metadata) != _identity(
            database_file_path_metadata
        ):
            raise CodeQLRustQualityError(
                "Rust CodeQL database metadata changed while it was being opened"
            )

        runner_temp_descriptor = os.open(runner_temp, _directory_open_flags())
        runner_temp_metadata = os.fstat(runner_temp_descriptor)
        _require_owned_directory_metadata(
            runner_temp_metadata, "fixed CodeQL temporary parent"
        )
        if _identity(runner_temp_metadata) != _identity(runner_temp_path_metadata):
            raise CodeQLRustQualityError(
                "fixed CodeQL temporary parent changed while it was being opened"
            )
        return _FixedCodeQLPathBindings(
            codeql=codeql,
            database=database,
            runner_temp=runner_temp,
            codeql_descriptor=codeql_descriptor,
            database_descriptor=database_descriptor,
            database_metadata_descriptor=database_metadata_descriptor,
            runner_temp_descriptor=runner_temp_descriptor,
            codeql_identity=_identity(codeql_metadata),
            database_identity=_identity(database_metadata),
            database_metadata_identity=_identity(database_file_metadata),
            runner_temp_identity=_identity(runner_temp_metadata),
            threads=configuration.threads,
            ram_mb=configuration.ram_mb,
        )
    except BaseException as primary:
        cleanup_error: BaseException | None = None
        try:
            _close_binding_descriptors(
                (
                    (database_metadata_descriptor, "database-metadata"),
                    (database_descriptor, "database"),
                    (runner_temp_descriptor, "temporary-parent"),
                    (codeql_descriptor, "binary"),
                )
            )
        except BaseException as exc:
            cleanup_error = exc
        if cleanup_error is not None:
            cleanup_message = f"cleanup also failed: {cleanup_error}"
            if not isinstance(primary, Exception):
                primary.add_note(cleanup_message)
                raise
            if not isinstance(cleanup_error, Exception):
                cleanup_error.add_note(
                    f"while handling CodeQL path-binding failure: {primary}"
                )
                raise cleanup_error from primary
            if isinstance(primary, OSError):
                raise CodeQLRustQualityError(
                    "cannot open fixed Rust CodeQL path binding: "
                    f"{primary}; {cleanup_message}"
                ) from primary
            _merge_cleanup_failure(primary, cleanup_message)
        if isinstance(primary, OSError):
            raise CodeQLRustQualityError(
                f"cannot open fixed Rust CodeQL path binding: {primary}"
            ) from primary
        raise


def _revalidate_fixed_codeql_bindings(
    bindings: _FixedCodeQLPathBindings,
) -> None:
    codeql_path_metadata = _canonical_fixed_metadata(
        bindings.codeql, "fixed CodeQL binary"
    )
    codeql_metadata = os.fstat(bindings.codeql_descriptor)
    _require_codeql_metadata(codeql_metadata)
    if not (
        _identity(codeql_path_metadata)
        == _identity(codeql_metadata)
        == bindings.codeql_identity
    ):
        raise CodeQLRustQualityError("fixed CodeQL binary identity changed")

    database_path_metadata = _canonical_fixed_metadata(
        bindings.database, "fixed Rust CodeQL database"
    )
    database_metadata = os.fstat(bindings.database_descriptor)
    _require_owned_directory_metadata(
        database_metadata, "fixed Rust CodeQL database"
    )
    if not (
        _identity(database_path_metadata)
        == _identity(database_metadata)
        == bindings.database_identity
    ):
        raise CodeQLRustQualityError("fixed Rust CodeQL database identity changed")
    database_file_path_metadata = os.stat(
        "codeql-database.yml",
        dir_fd=bindings.database_descriptor,
        follow_symlinks=False,
    )
    database_file_metadata = os.fstat(bindings.database_metadata_descriptor)
    if not (
        _identity(database_file_path_metadata)
        == _identity(database_file_metadata)
        == bindings.database_metadata_identity
    ):
        raise CodeQLRustQualityError("Rust CodeQL database metadata identity changed")
    _require_database_metadata(database_file_path_metadata)
    _require_database_metadata(database_file_metadata)

    runner_temp_path_metadata = _canonical_fixed_metadata(
        bindings.runner_temp, "fixed CodeQL temporary parent"
    )
    runner_temp_metadata = os.fstat(bindings.runner_temp_descriptor)
    _require_owned_directory_metadata(
        runner_temp_metadata, "fixed CodeQL temporary parent"
    )
    if not (
        _identity(runner_temp_path_metadata)
        == _identity(runner_temp_metadata)
        == bindings.runner_temp_identity
    ):
        raise CodeQLRustQualityError("fixed CodeQL temporary parent identity changed")


def _close_fixed_codeql_bindings(
    bindings: _FixedCodeQLPathBindings,
) -> None:
    _close_binding_descriptors(
        (
            (bindings.database_metadata_descriptor, "database-metadata"),
            (bindings.database_descriptor, "database"),
            (bindings.runner_temp_descriptor, "temporary-parent"),
            (bindings.codeql_descriptor, "binary"),
        )
    )


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


def _run_query(
    bindings: _FixedCodeQLPathBindings,
    query: pathlib.Path,
    output: pathlib.Path,
) -> None:
    _revalidate_fixed_codeql_bindings(bindings)
    try:
        result = capture_stdout(
            [
                os.fspath(bindings.codeql),
                "query",
                "run",
                "--warnings=error",
                f"--threads={bindings.threads}",
                f"--ram={bindings.ram_mb}",
                f"--database={bindings.database}",
                f"--output={output}",
                "--",
                str(query),
            ],
            timeout_seconds=(
                CODEQL_METRICS_TIMEOUT_SECONDS
                if query == METRICS_QUERY
                else CODEQL_COMMAND_TIMEOUT_SECONDS
            ),
            timeout_policy=(
                TimeoutPolicy.LONG_ANALYSIS
                if query == METRICS_QUERY
                else TimeoutPolicy.STANDARD
            ),
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
    _revalidate_fixed_codeql_bindings(bindings)


def _decode_query(
    bindings: _FixedCodeQLPathBindings,
    bqrs: pathlib.Path,
) -> list[list[object]]:
    _revalidate_fixed_codeql_bindings(bindings)
    try:
        result = capture_stdout(
            [
                os.fspath(bindings.codeql),
                "bqrs",
                "decode",
                "--format=json",
                str(bqrs),
            ],
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
    _revalidate_fixed_codeql_bindings(bindings)
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


def validate_extraction_quality(
    tracked: frozenset[str],
    extracted: frozenset[str],
    metrics: Mapping[str, int],
) -> None:
    """Check extraction integrity; macro coverage requires target validation too."""
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
    for name in sorted(ZERO_METRICS - {"unresolved_source_macro_calls"}):
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


def validate_quality(
    tracked: frozenset[str],
    extracted: frozenset[str],
    metrics: Mapping[str, int],
) -> None:
    """Retain the original single-database contract for existing callers."""
    validate_extraction_quality(tracked, extracted, metrics)
    if metrics["unresolved_source_macro_calls"] != 0:
        raise CodeQLRustQualityError(
            "unresolved_source_macro_calls must be zero, "
            f"got {metrics['unresolved_source_macro_calls']}"
        )


def main() -> None:
    try:
        require_repository_target_absent()
        expected_commit = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
        if not expected_commit:
            raise CodeQLRustQualityError("expected checkout commit is missing")
        require_clean_checkout(expected_commit)
        tracked = tracked_rust_paths()
        bindings = _open_fixed_codeql_bindings()
        binding_primary: BaseException | None = None
        try:
            with tempfile.TemporaryDirectory(
                prefix="qperiapt-codeql-quality.", dir=bindings.runner_temp
            ) as temporary:
                output_dir = pathlib.Path(temporary)
                paths_bqrs = output_dir / "extracted-paths.bqrs"
                metrics_bqrs = output_dir / "metrics.bqrs"
                unresolved_bqrs = output_dir / "unresolved-macros.bqrs"
                _run_query(bindings, EXTRACTED_PATHS_QUERY, paths_bqrs)
                _run_query(bindings, METRICS_QUERY, metrics_bqrs)
                _run_query(
                    bindings, UNRESOLVED_MACROS_QUERY, unresolved_bqrs
                )
                extracted = _parse_extracted_paths(
                    _decode_query(bindings, paths_bqrs)
                )
                metrics = _parse_metrics(
                    _decode_query(bindings, metrics_bqrs)
                )
                unresolved = _parse_unresolved_macros(
                    _decode_query(bindings, unresolved_bqrs)
                )
                unresolved_metric = metrics["unresolved_source_macro_calls"]
                validate_unresolved_detail_count(unresolved_metric, unresolved)
                if unresolved:
                    print(
                        "CODEQL_RUST_UNRESOLVED_MACROS "
                        + json.dumps(
                            unresolved,
                            ensure_ascii=True,
                            separators=(",", ":"),
                        )
                    )
        except BaseException as exc:
            binding_primary = exc
            raise
        finally:
            try:
                _close_fixed_codeql_bindings(bindings)
            except CodeQLRustQualityError as cleanup_error:
                if binding_primary is not None:
                    _merge_cleanup_failure(
                        binding_primary,
                        "CodeQL path-binding cleanup also failed: "
                        f"{cleanup_error}",
                    )
                else:
                    raise
        validate_quality(tracked, extracted, metrics)
        require_repository_target_absent()
        require_clean_checkout(expected_commit)
    except OSError as exc:
        raise SystemExit(
            f"error: Rust CodeQL path-binding filesystem operation failed: {exc}"
        ) from exc
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
