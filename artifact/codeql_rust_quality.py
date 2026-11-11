#!/usr/bin/env python3
"""Fail-closed quality gate for the same-run Rust CodeQL database."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence

from bounded_process import BoundedProcessError, capture_stdout
from evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import GitProvenanceError, inspect_worktree, run_git_bytes


ARTIFACT_DIR = pathlib.Path(__file__).resolve(strict=True).parent
REPOSITORY_ROOT = ARTIFACT_DIR.parent
QUERY_DIR = ARTIFACT_DIR / "codeql-rust-quality"
EXTRACTED_PATHS_QUERY = QUERY_DIR / "ExtractedPaths.ql"
METRICS_QUERY = QUERY_DIR / "Metrics.ql"
UNRESOLVED_MACROS_QUERY = QUERY_DIR / "UnresolvedMacros.ql"
FIXED_CODEQL_BINARY = pathlib.Path(
    "/opt/hostedtoolcache/CodeQL/2.26.2/x64/codeql/codeql"
)
FIXED_CODEQL_DATABASE = pathlib.Path(
    "/home/runner/work/_temp/qperiapt-codeql-database/rust"
)
FIXED_RUNNER_TEMP = pathlib.Path("/home/runner/work/_temp")
# Keep current compiler inputs and pinned paper snapshots in the full extraction.
EXPECTED_CURRENT_RUST_SOURCE_COUNT = 106
EXPECTED_ARCHIVED_RUST_SOURCE_COUNT = 68
ARCHIVE_ROOT = "paper/continuity/artifacts/bootstrap"
EXPECTED_TRACKED_RUST_SOURCE_COUNT = EXPECTED_CURRENT_RUST_SOURCE_COUNT + EXPECTED_ARCHIVED_RUST_SOURCE_COUNT
CODEQL_COMMAND_TIMEOUT_SECONDS = 300
CODEQL_QUERY_THREADS = 4
CODEQL_QUERY_RAM_MB = 14_000
MAX_CODEQL_QUERY_DIAGNOSTIC_BYTES = 4 * 1024 * 1024
MAX_CODEQL_DECODED_JSON_BYTES = 16 * 1024 * 1024
ARCHIVE_SEMANTICS_MESSAGE = (
    "semantic analyzer unavailable (not included in files loaded from manifest)"
)
ARCHIVE_SEMANTICS_FULL_MESSAGE = ARCHIVE_SEMANTICS_MESSAGE + ": macro expansion will be skipped."
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
class SourcePacket:
    source_commit: str
    pins_sha256: str
    rust_sources: int


# The pinned manifests enumerate each source path, byte length, SHA-256 and Git
# blob identity. CODEQL_RUST_ARCHIVES.md records the role of all 68 retained paths.
PAPER_ARCHIVE_PACKETS = {
    "ack": SourcePacket("471900bfe8070d1021a1feb67481437d599d80ba",
                        "cf9c16f4dc8069717c1a40386f96290cae0aec89c356f02f824d8b3143c73eb5", 19),
    "entry": SourcePacket("b1cff2a045d23aecf75aef12122e5080a8419676",
                          "f988feb7b4755624f1c1b03f436cdc47c4736dc911a3746d534d158157529447", 2),
    "initial": SourcePacket("471900bfe8070d1021a1feb67481437d599d80ba",
                            "56edba39cb6639b2b1ea251ec84bbdd86c38eaf838c6318b47624671f43452f2", 20),
    "reply": SourcePacket("68549dbc3ae4491d8b5edaa708548dc60743eab7",
                          "ac548057d4cf4ad06620117a4e5bed966727b941e08c10c90717a2d4d614f6ae", 18),
    "terminal": SourcePacket("360aa8107aa7df502108627a4dcf89f30d106594",
                             "52a2da009793fdb227548fafdc2caa5da33a69966e13c69169eb766e024895de", 9),
}


@dataclasses.dataclass(frozen=True)
class ArchivedRustSource:
    source_commit: str
    source_path: str
    size: int
    sha256: str
    git_blob: str


def pinned_archive_sources(root: pathlib.Path = REPOSITORY_ROOT) -> dict[str, ArchivedRustSource]:
    """Read the exact reviewed manifests, without accepting changed pin bytes."""
    sources = {}
    for name, packet in PAPER_ARCHIVE_PACKETS.items():
        directory = f"{ARCHIVE_ROOT}/{name}"
        pins = read_regular_snapshot(root / directory / "SOURCE_PINS.json",
                                     maximum=256 * 1024, label="paper Rust source pins")
        if pins.sha256 != packet.pins_sha256:
            raise ValueError(f"paper Rust source pin manifest differs: {name}")
        value = parse_strict_json_bytes(pins.data, label="paper Rust source pins")
        if (not isinstance(value, dict)
                or value.get("source_commit", value.get("base_commit")) != packet.source_commit
                or not isinstance(value.get("files"), list)):
            raise ValueError(f"paper Rust source pin identity differs: {name}")
        count = 0
        for record in value["files"]:
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise ValueError(f"paper Rust source pin is malformed: {name}")
            relative = record["path"]
            path = pathlib.PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
                raise ValueError(f"paper Rust source path is not canonical: {relative}")
            if path.suffix != ".rs":
                continue
            size, digest = record.get("bytes"), record.get("sha256")
            blob = record.get("git_blob", record.get("git_blob_sha1"))
            if (type(size) is not int or size <= 0
                    or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or not isinstance(blob, str) or re.fullmatch(r"[0-9a-f]{40}", blob) is None):
                raise ValueError(f"paper Rust source byte identity is malformed: {relative}")
            archived = f"{directory}/source/{relative}"
            if archived in sources:
                raise ValueError(f"paper Rust source pin is duplicated: {archived}")
            sources[archived] = ArchivedRustSource(packet.source_commit, relative, size, digest, blob)
            count += 1
        if count != packet.rust_sources:
            raise ValueError(f"paper Rust source packet count differs: {name}")
    if len(sources) != EXPECTED_ARCHIVED_RUST_SOURCE_COUNT:
        raise ValueError("paper Rust source inventory count differs")
    return sources


def validate_archive_inventory(root: pathlib.Path, tracked: frozenset[str]) -> frozenset[str]:
    """Keep every frozen source extracted and reject executable archive roots."""
    sources = pinned_archive_sources(root)
    observed = {path for path in tracked if path.startswith(ARCHIVE_ROOT + "/")}
    if observed != sources.keys():
        raise ValueError("paper Rust source path inventory differs")
    directories = {pathlib.PurePosixPath(ARCHIVE_ROOT)}
    for relative, expected in sources.items():
        snapshot = read_regular_snapshot(root / relative, maximum=5 * 1024**2,
                                         label="archived paper Rust source")
        blob = hashlib.sha1(b"blob " + str(snapshot.size).encode("ascii") + b"\0" + snapshot.data).hexdigest()
        if (snapshot.size != expected.size or snapshot.sha256 != expected.sha256
                or blob != expected.git_blob):
            raise ValueError(f"archived paper Rust source bytes differ: {relative}")
        parent = pathlib.PurePosixPath(relative).parent
        while parent.as_posix() != ARCHIVE_ROOT:
            directories.add(parent)
            parent = parent.parent
    for relative in sorted(directories):
        manifest = root / relative / "Cargo.toml"
        if manifest.exists() or manifest.is_symlink():
            raise ValueError(f"archived paper Rust source has a Cargo manifest: {relative}")
    return frozenset(sources)


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


def _open_fixed_codeql_bindings() -> _FixedCodeQLPathBindings:
    if sys.platform != "linux":
        raise CodeQLRustQualityError(
            "fixed Rust CodeQL path bindings require the Linux analysis lane"
        )
    codeql_path_metadata = _canonical_fixed_metadata(
        FIXED_CODEQL_BINARY, "fixed CodeQL binary"
    )
    database_path_metadata = _canonical_fixed_metadata(
        FIXED_CODEQL_DATABASE, "fixed Rust CodeQL database"
    )
    runner_temp_path_metadata = _canonical_fixed_metadata(
        FIXED_RUNNER_TEMP, "fixed CodeQL temporary parent"
    )
    try:
        FIXED_CODEQL_DATABASE.relative_to(FIXED_RUNNER_TEMP)
    except ValueError as exc:
        raise CodeQLRustQualityError(
            "fixed Rust CodeQL database must be under the fixed temporary parent"
        ) from exc
    codeql_descriptor = -1
    database_descriptor = -1
    database_metadata_descriptor = -1
    runner_temp_descriptor = -1
    try:
        codeql_descriptor = os.open(FIXED_CODEQL_BINARY, _file_open_flags())
        codeql_metadata = os.fstat(codeql_descriptor)
        _require_codeql_metadata(codeql_metadata)
        if _identity(codeql_metadata) != _identity(codeql_path_metadata):
            raise CodeQLRustQualityError(
                "fixed CodeQL binary changed while it was being opened"
            )

        database_descriptor = os.open(
            FIXED_CODEQL_DATABASE, _directory_open_flags()
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

        runner_temp_descriptor = os.open(FIXED_RUNNER_TEMP, _directory_open_flags())
        runner_temp_metadata = os.fstat(runner_temp_descriptor)
        _require_owned_directory_metadata(
            runner_temp_metadata, "fixed CodeQL temporary parent"
        )
        if _identity(runner_temp_metadata) != _identity(runner_temp_path_metadata):
            raise CodeQLRustQualityError(
                "fixed CodeQL temporary parent changed while it was being opened"
            )
        return _FixedCodeQLPathBindings(
            codeql=FIXED_CODEQL_BINARY,
            database=FIXED_CODEQL_DATABASE,
            runner_temp=FIXED_RUNNER_TEMP,
            codeql_descriptor=codeql_descriptor,
            database_descriptor=database_descriptor,
            database_metadata_descriptor=database_metadata_descriptor,
            runner_temp_descriptor=runner_temp_descriptor,
            codeql_identity=_identity(codeql_metadata),
            database_identity=_identity(database_metadata),
            database_metadata_identity=_identity(database_file_metadata),
            runner_temp_identity=_identity(runner_temp_metadata),
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
    try:
        archived = validate_archive_inventory(root, rust_paths)
    except (OSError, ValueError) as exc:
        raise CodeQLRustQualityError(f"cannot validate archived Rust sources: {exc}") from exc
    if len(rust_paths - archived) != EXPECTED_CURRENT_RUST_SOURCE_COUNT:
        raise CodeQLRustQualityError("current Rust source inventory count differs")
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
                f"--threads={CODEQL_QUERY_THREADS}",
                f"--ram={CODEQL_QUERY_RAM_MB}",
                f"--database={bindings.database}",
                f"--output={output}",
                "--",
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


def _parse_file_details(
    rows: Sequence[Sequence[object]],
) -> dict[str, tuple[int, int]]:
    details: dict[str, tuple[int, int]] = {}
    for row in rows:
        if (len(row) != 3 or not isinstance(row[0], str)
                or any(type(value) is not int or value < 0 for value in row[1:])):
            raise CodeQLRustQualityError("file-detail query returned a malformed row")
        path = next(iter(_parse_extracted_paths([[row[0]]])))
        if path in details:
            raise CodeQLRustQualityError("file-detail query contains duplicate paths")
        details[path] = (row[1], row[2])
    return details


def _parse_extraction_diagnostics(
    rows: Sequence[Sequence[object]],
) -> tuple[tuple[str, str, str, str, str, int, int], ...]:
    details: list[tuple[str, str, str, str, str, int, int]] = []
    for row in rows:
        if (len(row) != 7
                or any(not isinstance(value, str) or not value for value in row[:5])
                or row[1] not in {"Warning", "Error"}
                or any(type(value) is not int or value < 1 for value in row[5:])):
            raise CodeQLRustQualityError("extraction-diagnostic query returned a malformed row")
        _parse_extracted_paths([[row[0]]])
        details.append(tuple(row))
    if len(details) != len(set(details)):
        raise CodeQLRustQualityError("extraction-diagnostic query contains duplicate rows")
    return tuple(details)


def _parse_quality_rows(
    rows: Sequence[Sequence[object]],
) -> tuple[dict[str, int], dict[str, tuple[int, int]],
           tuple[tuple[str, str, str, str, str, int, int], ...]]:
    metrics: list[list[object]] = []
    files: list[list[object]] = []
    diagnostics: list[list[object]] = []
    for row in rows:
        if (len(row) != 7 or not isinstance(row[0], str)
                or not isinstance(row[1], str)
                or type(row[2]) is not int or type(row[3]) is not int
                or any(not isinstance(value, str) for value in row[4:])):
            raise CodeQLRustQualityError("quality query returned a malformed tagged row")
        kind, name, first, second, tag, message, full_message = row
        if kind in {"metric", "file"}:
            if tag or message or full_message or (kind == "metric" and second != 0):
                raise CodeQLRustQualityError("quality query returned unexpected row fields")
            if kind == "metric":
                metrics.append([name, first])
            else:
                files.append([name, first, second])
        elif kind in {"Warning", "Error"}:
            diagnostics.append([name, kind, tag, message, full_message, first, second])
        else:
            raise CodeQLRustQualityError(f"quality query returned an unknown row kind: {kind}")
    return (_parse_metrics(metrics), _parse_file_details(files),
            _parse_extraction_diagnostics(diagnostics))


def validate_current_and_archive_quality(
    tracked: frozenset[str],
    extracted: frozenset[str],
    metrics: Mapping[str, int],
    files: Mapping[str, tuple[int, int]],
    diagnostics: Sequence[tuple[str, str, str, str, str, int, int]],
    unresolved: Sequence[tuple[str, int, int, str]],
) -> None:
    """Qualify all source bytes and the current Cargo compilation separately.

    The original queries still analyze the complete database. A frozen partial
    export has no Cargo semantic context: the sole admitted diagnostic is bound
    to the reviewed file bytes and the exact CLI 2.26.2 diagnostic, not a path
    prefix or an unrestricted warning/macro allowance.
    """
    try:
        archived = validate_archive_inventory(REPOSITORY_ROOT, tracked)
    except (OSError, EvidenceIOError, ValueError) as exc:
        raise CodeQLRustQualityError(f"cannot validate archived Rust sources: {exc}") from exc
    if not archived <= tracked:
        raise CodeQLRustQualityError("archive inventory is outside tracked Rust sources")
    current = tracked - archived
    if files.keys() != tracked:
        raise CodeQLRustQualityError("all extracted path set differs from tracked Rust sources")
    if metrics["extracted_files"] != len(tracked):
        raise CodeQLRustQualityError("extracted file metric differs from the complete inventory")
    for index, name in enumerate(("source_macro_calls", "source_format_args")):
        if sum(values[index] for values in files.values()) != metrics[name]:
            raise CodeQLRustQualityError(f"per-file {name} count differs from its metric")
    for severity, name in (("Error", "extraction_errors"), ("Warning", "extraction_warnings")):
        if sum(row[1] == severity for row in diagnostics) != metrics[name]:
            raise CodeQLRustQualityError(f"{name} detail count differs from its metric")
    archive_warnings: set[str] = set()
    for path, severity, tag, message, full_message, line, column in diagnostics:
        if (path not in archived or severity != "Warning" or tag != "semantics"
                or message != ARCHIVE_SEMANTICS_MESSAGE
                or full_message != ARCHIVE_SEMANTICS_FULL_MESSAGE
                or (line, column) != (1, 1)
                or path in archive_warnings):
            raise CodeQLRustQualityError(f"unqualified extraction diagnostic at {path}")
        archive_warnings.add(path)
    if archive_warnings != archived:
        raise CodeQLRustQualityError("archive semantic-context diagnostic inventory differs")
    validate_unresolved_detail_count(metrics["unresolved_source_macro_calls"], unresolved)
    unresolved_by_path: dict[str, int] = {}
    for path, _line, _column, _text in unresolved:
        if path not in archived:
            raise CodeQLRustQualityError(f"unresolved current-source macro at {path}")
        unresolved_by_path[path] = unresolved_by_path.get(path, 0) + 1
    for path, count in unresolved_by_path.items():
        if count > files[path][0]:
            raise CodeQLRustQualityError(f"unresolved macro count exceeds all macros at {path}")
    current_metrics = dict(metrics)
    current_metrics.update({
        "extracted_files": len(current),
        "extraction_warnings": metrics["extraction_warnings"] - len(archive_warnings),
        "unresolved_source_macro_calls": 0,
        "source_macro_calls": sum(files[path][0] for path in current),
        "source_format_args": sum(files[path][1] for path in current),
    })
    # Every other zero metric, internal consistency equation and current-source
    # sentinel is checked by the unchanged strict gate.
    validate_quality(current, extracted, current_metrics)


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
                metrics, files, diagnostics = _parse_quality_rows(
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
        validate_current_and_archive_quality(
            tracked, extracted, metrics, files, diagnostics, unresolved
        )
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
        f"current_rs={EXPECTED_CURRENT_RUST_SOURCE_COUNT} "
        f"pinned_archive_rs={EXPECTED_ARCHIVED_RUST_SOURCE_COUNT} "
        f"archive_semantics_warnings={len(diagnostics)} "
        f"archive_unresolved_macros={len(unresolved)} "
        f"source_macro_calls={metrics['source_macro_calls']} "
        f"source_format_args={metrics['source_format_args']}"
    )


if __name__ == "__main__":
    main()
