"""Opt-in production admission for the fixed Stage3/Stage4 SummaryStats plan.

Extraction keeps its existing hosted tool and target-quality contract. Only an
explicit projection analysis creates this private runtime; its archive, vendor
patch, query roots and complete compiled capsule are checked before execution
and again before its receipt can enter publication. This module does not fetch
an archive, compile a query, select a smaller suite or upload SARIF.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

import codeql_evaluator_logs as evaluator_logs
import codeql_rust_quality as quality
import codeql_summary_plan as capsule
import codeql_summary_projection as projection
from evidence_io import (consume_regular_snapshot, fresh_output_directory,
                         parse_strict_json_bytes, read_regular_snapshot)


MODES = ("none", "projection")
PRODUCTION_MANIFEST_SHA256 = "2b961807f0147058e7c2012586a3f5c67d7b718b7ed86ea92bf6ec25087632c1"
STAGE34_COMPILER_KEY = "0ee092250be1b05f03b994a868d639cc"
LAUNCHER_SHA256 = "5010324098d11f9e2d34e0fcf53bb44e40e8e3ffc8aecefe695269b54edaa413"
PACK_RELATIVE = "qlpacks/codeql/rust-queries/0.1.44"
# Derived by streaming the exact authenticated archive, excluding only the
# target pack whose original/effective identities are admitted by projection.
RUNTIME_INVENTORY_SHA256 = "1d61c12cb67e01730a1ec5031aefe669035e52290081dc6822333cb5ab861c90"
RUNTIME_FILE_COUNT = 2282
RUNTIME_TOTAL_BYTES = 231156107
MAX_RUNTIME_FILES = 5000
MAX_RUNTIME_BYTES = 512 * 1024**2
MAX_RUNTIME_FILE_BYTES = 64 * 1024**2
MAX_RECEIPT_BYTES = 4 * 1024**2
PLAN_RECEIPT = "ANALYSIS_PLAN.json"
RUNTIME_RECEIPT = "ANALYSIS_RUNTIME.json"
QLCONFIG = b"{}\n"
OBSERVATION_FIELDS = (
    "schema", "logs", "query_starts", "query_completions",
    "precompiled_query_loads", "query_compilations", "evaluator_start_lines",
    "jvm_heap_mb_arguments", "off_heap_mb_observed",
)
UNADMITTED_DATABASE_PATHS = (
    "temp/analysisConfig.json", "temp/extensionPacks.json",
    "temp/config-queries.qls", "overlay-base-metadata",
    "overlay-path-transformer", "working/overlay",
)
require = capsule.require
canonical_sha = projection.canonical_sha


def expected_identity() -> dict:
    value = projection.expected_identity()
    require(value["manifest_sha256"] == PRODUCTION_MANIFEST_SHA256
            and value["compiler_inputs_digest"] == STAGE34_COMPILER_KEY,
            "production requires the fixed Stage3/Stage4 projection identity")
    return value


def write_json(path: Path, value: object) -> None:
    capsule.write_exclusive(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def frozen_suite(pack: Path, queries: dict) -> bytes:
    return "".join("- query: " + json.dumps(str(pack / relative)) + "\n"
                   for relative in sorted(queries)).encode()


def controlled_environment(environment: dict[str, str], temporary: Path) -> dict[str, str]:
    """Keep runner tracking and explicit tool inputs without inherited overrides."""
    result = {"PATH": "/usr/bin:/bin", "TMPDIR": str(temporary),
              "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    for name in ("RUNNER_TRACKING_ID", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                 "CODEQL_EXPECTED_COMMIT"):
        if name in environment:
            result[name] = environment[name]
    return result


def runtime_inventory(root: Path) -> dict:
    require(root.is_absolute() and root.resolve(strict=True) == root and not root.is_symlink(),
            "analysis runtime root is not canonical")
    result = {}
    total_bytes = directories = 0
    for parent, child_names, file_names in os.walk(root, followlinks=False):
        directory = Path(parent)
        directories += 1
        require(directories <= MAX_RUNTIME_FILES, "analysis runtime directory census exceeds its bound")
        retained = []
        for name in sorted(child_names):
            child = directory / name
            require(child.is_dir() and not child.is_symlink(),
                    "analysis runtime contains a nonregular directory")
            if child.relative_to(root).as_posix() != PACK_RELATIVE:
                retained.append(name)
        child_names[:] = retained
        for name in sorted(file_names):
            path = directory / name
            require(len(result) < MAX_RUNTIME_FILES, "analysis runtime file census exceeds its bound")
            modes = []

            def validate_metadata(metadata: os.stat_result) -> None:
                require(metadata.st_uid == os.geteuid() and metadata.st_nlink == 1,
                        "analysis runtime file ownership or links differ")
                modes.append(stat.S_IMODE(metadata.st_mode))

            snapshot = consume_regular_snapshot(path, maximum=MAX_RUNTIME_FILE_BYTES,
                                                label="analysis runtime file",
                                                validate_metadata=validate_metadata)
            total_bytes += snapshot.size
            require(total_bytes <= MAX_RUNTIME_BYTES and modes[0] & 0o022 == 0,
                    "analysis runtime size or writable mode differs")
            result[path.relative_to(root).as_posix()] = {
                "bytes": snapshot.size, "sha256": snapshot.sha256, "mode": modes[0],
            }
    validate_runtime_inventory(result)
    return result


def validate_runtime_inventory(value: object) -> None:
    require(isinstance(value, dict) and 0 < len(value) <= MAX_RUNTIME_FILES,
            "analysis runtime inventory is malformed")
    total_bytes = 0
    for name, entry in value.items():
        require(isinstance(name, str) and bool(name), "analysis runtime member path is malformed")
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and relative.as_posix() == name and "\\" not in name
                and not name.startswith(PACK_RELATIVE + "/"),
                "analysis runtime member path differs")
        require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "mode"}
                and type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_RUNTIME_FILE_BYTES
                and isinstance(entry["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None
                and type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777
                and entry["mode"] & 0o022 == 0,
                "analysis runtime member identity is malformed")
        total_bytes += entry["bytes"]
    require(total_bytes <= MAX_RUNTIME_BYTES, "analysis runtime byte census exceeds its bound")
    launcher = value.get("codeql", {})
    require(launcher.get("sha256") == LAUNCHER_SHA256 and launcher.get("mode", 0) & 0o100,
            "analysis runtime launcher identity differs")
    require(len(value) == RUNTIME_FILE_COUNT and total_bytes == RUNTIME_TOTAL_BYTES
            and canonical_sha(value) == RUNTIME_INVENTORY_SHA256,
            "complete official analysis runtime inventory differs")


def extract_runtime(archive: Path, destination: Path, command) -> Path:
    identity = expected_identity()
    require(not destination.exists() and not destination.is_symlink(),
            "analysis runtime destination must be fresh")
    destination.mkdir(mode=0o700)
    # The supervisor pins one linked, private regular file (nlink == 1).
    # Anonymous TemporaryFile may use O_TMPFILE/unlink and has nlink == 0.
    with tempfile.NamedTemporaryFile(mode="w+b", dir=destination, prefix="codeql-archive-") as source:
        snapshot = consume_regular_snapshot(
            archive, maximum=identity["tool_bundle_bytes"], label="production CodeQL archive",
            consume=source.write)
        require(snapshot.size == identity["tool_bundle_bytes"]
                and snapshot.sha256 == identity["tool_bundle_sha256"],
                "production CodeQL archive differs")
        source.flush()
        source.seek(0)
        # The held descriptor supplies the exact authenticated bytes; tar never
        # reopens the caller's archive pathname. Only the fixed official payload
        # is expanded into this fresh private destination.
        command("plan-extract", [
            "/usr/bin/tar", "--extract", "--zstd", "--file=-", "--no-same-owner",
            "--same-permissions", "--directory=" + str(destination),
        ], seconds=300, stdin_fd=source.fileno())
    require({path.name for path in destination.iterdir()} == {"codeql"},
            "analysis runtime archive top level differs")
    return destination / "codeql"


def admit_database(database: Path) -> dict:
    for relative in UNADMITTED_DATABASE_PATHS:
        path = database / relative
        require(not path.exists() and not path.is_symlink(),
                "analysis database contains unadmitted configuration: " + relative)
    metadata = read_regular_snapshot(database / "codeql-database.yml", maximum=1024**2,
                                     label="analysis database metadata")
    fields = capsule.database_metadata_fields(metadata.data.decode("utf-8"))
    require(fields.get("overlayBaseDatabase") == ["false"]
            and fields.get("overlayDatabase") == ["false"],
            "projection analysis requires an explicit non-overlay database")
    source_root = fields.get("sourceLocationPrefix")
    require(isinstance(source_root, list) and len(source_root) == 1 and bool(source_root[0]),
            "analysis database source root is missing or duplicated")
    return {"metadata_sha256": metadata.sha256, "source_root": source_root[0],
            "overlay_base": False, "overlay": False,
            "unadmitted_paths_absent": list(UNADMITTED_DATABASE_PATHS)}


@dataclass
class AnalysisContext:
    root: Path
    codeql: Path
    pack: Path
    suite: Path
    runtime: dict
    tool: dict
    before: dict
    database_before: dict
    after: dict | None = None
    database_after: dict | None = None


def prepare(run, archive: Path) -> AnalysisContext:
    identity = expected_identity()
    root = fresh_output_directory(run.output / "analysis-plan", within=run.output,
                                  label="production analysis plan")
    root.mkdir(mode=0o700)
    for name in ("tmp", "cache", "evaluator"):
        (root / name).mkdir(mode=0o700)
    capsule.write_exclusive(root / "qlconfig.yml", QLCONFIG)
    run.environment = controlled_environment(run.environment, root / "tmp")
    database_before = admit_database(run.configuration.database)
    result_root = run.configuration.database / "results/codeql/rust-queries"
    require(not result_root.exists() and not result_root.is_symlink(),
            "projection analysis requires fresh query results")
    tool_root = extract_runtime(archive, root / "tool", run.command)
    runtime = runtime_inventory(tool_root)
    codeql = tool_root / "codeql"
    tool = {key: identity[key] for key in
            ("codeql_version", "query_pack", "tool_bundle_bytes", "tool_bundle_sha256")}
    tool.update(codeql_sha256=LAUNCHER_SHA256, runtime_inventory_sha256=canonical_sha(runtime))
    query_manifest = read_regular_snapshot(projection.QUERY_MANIFEST, maximum=64 * 1024,
                                           label="production query manifest")
    capsule.validate_tool_identity(identity, tool, query_manifest_sha256=query_manifest.sha256)
    version = run.command("plan-version", [
        str(codeql), "version", "--format=terse",
    ]).decode().strip()
    require(version == identity["codeql_version"], "private analysis CodeQL version differs")
    pack = tool_root / PACK_RELATIVE
    before = projection.install(pack, run.evidence)
    require(before == identity, "installed production projection identity differs")
    queries = parse_strict_json_bytes(query_manifest.data, label="production query manifest")["queries"]
    suite = root / "frozen.qls"
    capsule.write_exclusive(suite, frozen_suite(pack, queries))
    write_json(run.evidence / RUNTIME_RECEIPT, {"schema": 1, "files": runtime})
    run.codeql = codeql
    return AnalysisContext(root, codeql, pack, suite, runtime, tool, before, database_before)


def analysis_command(context: AnalysisContext, database: Path, evidence: Path,
                     profile: str, memory_arguments: list[str]) -> list[str]:
    require(profile in ("native", "wasm", "macos"), "unknown projection analysis profile")
    require(memory_arguments == ["--ram=14000", "--off-heap-ram=9329"],
            "projection analysis memory policy differs")
    category = "/language:rust" if profile == "native" else "/language:rust/target:" + profile
    return [
        str(context.codeql), "database", "analyze", str(database), str(context.suite),
        "--format=sarif-latest", "--output=" + str(evidence / "results.sarif"),
        "--threads=4", *memory_arguments, "--threat-model=local", "--no-download",
        "--common-caches=" + str(context.root / "cache"), "--sarif-category=" + category,
        "--dynamic-join-order-mode=all", "--verbosity=progress",
        "--logdir=" + str(context.root / "evaluator"),
        "--qlconfig-file=" + str(context.root / "qlconfig.yml"),
    ]


@contextmanager
def guard(run, context: AnalysisContext):
    primary_failure = False
    try:
        yield
    except BaseException:
        primary_failure = True
        raise
    finally:
        try:
            require(runtime_inventory(context.codeql.parent) == context.runtime,
                    "analysis runtime changed during evaluation")
            context.after = projection.validate(context.pack)
            require(context.after == context.before, "projection plan changed during evaluation")
            context.database_after = admit_database(run.configuration.database)
            require(context.database_after["source_root"] == context.database_before["source_root"],
                    "analysis database source root changed")
            configuration = read_regular_snapshot(context.root / "qlconfig.yml", maximum=1024,
                                                   label="private QL configuration")
            require(configuration.data == QLCONFIG, "private QL configuration changed")
            write_json(run.evidence / "ANALYSIS_PLAN_AFTER.json", {
                "summary_plan": context.after, "tool": context.tool,
                "database": context.database_after, "qlconfig_sha256": configuration.sha256,
            })
        except BaseException as error:
            try:
                write_json(run.evidence / "ANALYSIS_PLAN_FAILURE.json", {
                    "type": type(error).__name__, "message": str(error),
                    "primary_analysis_failed": primary_failure,
                })
            except (OSError, ValueError):
                pass
            if not primary_failure:
                raise


def validate_observations(value: object, pack: Path, queries: dict, heap_mb: int, *,
                          completion: object) -> None:
    require(isinstance(value, dict) and set(value) == set(OBSERVATION_FIELDS)
            and type(value["schema"]) is int and value["schema"] == 1,
            "production evaluator observations are malformed")
    evaluator_logs.validate_loads(value, [str((pack / relative).with_suffix(".qlx"))
                                         for relative in queries])
    require(all(type(value[key]) is int for key in
                ("query_starts", "query_completions", "query_compilations", "evaluator_start_lines"))
            and value["query_starts"] == 39 and 0 <= value["query_completions"] <= 39
            and value["query_compilations"] == 0 and value["evaluator_start_lines"] == 1,
            "production evaluator execution census differs")
    # Internal logs can omit a completion progress message even when the CLI
    # retains it on stderr. Preserve that log count, and bind the complete
    # per-query completion set to the independently read original stderr.
    require(isinstance(completion, dict) and set(completion) == {
                "schema", "source", "bytes", "sha256", "queries"}
            and type(completion["schema"]) is int and completion["schema"] == 1
            and completion["source"] == "analyze.stderr"
            and type(completion["bytes"]) is int and 0 < completion["bytes"] <= 16 * 1024**2
            and isinstance(completion["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", completion["sha256"]) is not None
            and completion["queries"] == sorted(queries) and len(queries) == 39,
            "production stderr completion census or identity differs")
    require(type(heap_mb) is int and 0 < heap_mb <= 14000 - 9329
            and value["jvm_heap_mb_arguments"] == [heap_mb]
            and value["off_heap_mb_observed"] == [9329],
            "production evaluator invocation allocation differs")
    logs = value["logs"]
    require(isinstance(logs, list) and 0 < len(logs) <= 128,
            "production evaluator log census differs")
    paths = set()
    total_bytes = 0
    for item in logs:
        require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}
                and isinstance(item["path"], str)
                and re.fullmatch(r"evaluator/execute-queries-[A-Za-z0-9_.-]+\.log", item["path"]) is not None
                and item["path"] not in paths
                and type(item["bytes"]) is int and 0 < item["bytes"] <= 2 * 1024**3
                and isinstance(item["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None,
                "production evaluator log identity differs")
        paths.add(item["path"])
        total_bytes += item["bytes"]
    require(total_bytes <= 4 * 1024**3, "production evaluator log byte census exceeds its bound")


def complete(run, context: AnalysisContext, analysis: dict, command: list[str], queries: dict) -> str:
    require(context.after == context.before == expected_identity()
            and context.database_after is not None,
            "production analysis has no successful plan postcheck")
    failure = run.evidence / "ANALYSIS_PLAN_FAILURE.json"
    require(not failure.exists() and not failure.is_symlink(),
            "production analysis plan postcheck failed")
    observed = evaluator_logs.observe(context.root, pattern="execute-queries-*.log",
                                      stdio_prefix=None, capture_invocation=True)
    observations = {key: observed[key] for key in OBSERVATION_FIELDS}
    completion = evaluator_logs.read_completion_receipt(run.evidence / "analyze.stderr", queries)
    memory = parse_strict_json_bytes(read_regular_snapshot(
        run.evidence / "QUERY_MEMORY.json", maximum=64 * 1024,
        label="analysis memory receipt").data, label="analysis memory receipt")
    validate_observations(observations, context.pack, queries, memory["heap_mb"], completion=completion)
    record = {
        "schema": 2, "kind": "qperiapt.codeql_rust_projection_analysis", "completed": True,
        "summary_plan_mode": "projection",
        **{key: analysis[key] for key in
           ("profile", "target", "source_commit", "run_id", "run_attempt", "query_inventory_sha256")},
        "summary_plan_before": context.before, "summary_plan_after": context.after,
        "tool": context.tool,
        "runtime_receipt_sha256": read_regular_snapshot(
            run.evidence / RUNTIME_RECEIPT, maximum=MAX_RECEIPT_BYTES,
            label="analysis runtime receipt").sha256,
        "database_before": context.database_before, "database_after": context.database_after,
        "query_command": command, "observations": observations, "completion_stderr": completion,
        "suite_sha256": read_regular_snapshot(context.suite, maximum=64 * 1024,
                                              label="frozen production suite").sha256,
        "qlconfig_sha256": hashlib.sha256(QLCONFIG).hexdigest(),
        "postcheck_receipt_sha256": read_regular_snapshot(
            run.evidence / "ANALYSIS_PLAN_AFTER.json", maximum=MAX_RECEIPT_BYTES,
            label="analysis plan postcheck").sha256,
    }
    write_json(run.evidence / PLAN_RECEIPT, record)
    return read_regular_snapshot(run.evidence / PLAN_RECEIPT, maximum=MAX_RECEIPT_BYTES,
                                 label="analysis plan receipt").sha256


def validate_publication(directory: Path, analysis: dict, *, expected_mode: str = "none") -> None:
    require(expected_mode in MODES, "unknown production summary plan mode")
    if expected_mode == "none":
        require(type(analysis.get("schema")) is int and analysis["schema"] == 2
                and "summary_plan_mode" not in analysis and "analysis_plan_sha256" not in analysis
                and not any(path.name.startswith(("ANALYSIS_PLAN", "SUMMARY_PLAN"))
                            or path.name == RUNTIME_RECEIPT for path in directory.iterdir()),
                "default production publication contains a projection plan")
        return
    require(type(analysis.get("schema")) is int and analysis["schema"] == 3
            and analysis.get("summary_plan_mode") == "projection",
            "projection production publication has no explicit plan identity")
    snapshot = read_regular_snapshot(directory / PLAN_RECEIPT, maximum=MAX_RECEIPT_BYTES,
                                     label="published analysis plan")
    require(snapshot.sha256 == analysis.get("analysis_plan_sha256"),
            "published analysis plan digest differs")
    record = parse_strict_json_bytes(snapshot.data, label="published analysis plan")
    keys = {
        "schema", "kind", "completed", "summary_plan_mode", "profile", "target", "source_commit",
        "run_id", "run_attempt", "query_inventory_sha256", "summary_plan_before", "summary_plan_after",
        "tool", "runtime_receipt_sha256", "database_before", "database_after", "query_command",
        "observations", "completion_stderr", "suite_sha256", "qlconfig_sha256", "postcheck_receipt_sha256",
    }
    require(isinstance(record, dict) and set(record) == keys
            and type(record["schema"]) is int and record["schema"] == 2
            and record["kind"] == "qperiapt.codeql_rust_projection_analysis"
            and record["completed"] is True and record["summary_plan_mode"] == "projection"
            and all(record[key] == analysis.get(key) for key in
                    ("profile", "target", "source_commit", "run_id", "run_attempt", "query_inventory_sha256")),
            "published analysis plan schema or workflow identity differs")
    identity = expected_identity()
    require(record["summary_plan_before"] == record["summary_plan_after"] == identity,
            "published analysis projection identity differs")
    runtime_snapshot = read_regular_snapshot(directory / RUNTIME_RECEIPT, maximum=MAX_RECEIPT_BYTES,
                                             label="published analysis runtime")
    require(runtime_snapshot.sha256 == record["runtime_receipt_sha256"],
            "published runtime receipt digest differs")
    runtime = parse_strict_json_bytes(runtime_snapshot.data, label="published analysis runtime")
    require(isinstance(runtime, dict) and set(runtime) == {"schema", "files"}
            and type(runtime["schema"]) is int and runtime["schema"] == 1,
            "published runtime receipt schema differs")
    validate_runtime_inventory(runtime["files"])
    tool = {key: identity[key] for key in
            ("codeql_version", "query_pack", "tool_bundle_bytes", "tool_bundle_sha256")}
    tool.update(codeql_sha256=LAUNCHER_SHA256, runtime_inventory_sha256=canonical_sha(runtime["files"]))
    require(record["tool"] == tool, "published private runtime identity differs")
    profile = analysis.get("profile")
    require(profile in ("native", "wasm", "macos"), "unknown published projection profile")
    configuration = quality.hosted_configuration("linux")
    output = configuration.runner_temp / ("qperiapt-codeql-" + profile)
    root = output / "analysis-plan"
    codeql = root / "tool/codeql/codeql"
    context = AnalysisContext(root, codeql, codeql.parent / PACK_RELATIVE, root / "frozen.qls",
                              runtime["files"], tool, identity, record["database_before"])
    require(record["query_command"] == analysis_command(
        context, configuration.database, output / "evidence", profile,
        ["--ram=14000", "--off-heap-ram=9329"]),
        "published projection analysis command differs")
    queries = parse_strict_json_bytes(read_regular_snapshot(
        projection.QUERY_MANIFEST, maximum=64 * 1024,
        label="published projection query manifest").data,
        label="published projection query manifest")["queries"]
    require(record["suite_sha256"] == hashlib.sha256(frozen_suite(context.pack, queries)).hexdigest()
            and record["qlconfig_sha256"] == hashlib.sha256(QLCONFIG).hexdigest(),
            "published frozen suite or QL configuration identity differs")
    memory = parse_strict_json_bytes(read_regular_snapshot(
        directory / "QUERY_MEMORY.json", maximum=64 * 1024,
        label="published analysis memory receipt").data, label="published analysis memory receipt")
    completion = evaluator_logs.read_completion_receipt(directory / "analyze.stderr", queries)
    require(record["completion_stderr"] == completion,
            "published completion stderr differs from its bound receipt")
    validate_observations(record["observations"], context.pack, queries, memory["heap_mb"],
                          completion=completion)
    for side in ("database_before", "database_after"):
        database = record[side]
        require(isinstance(database, dict) and set(database) == {
                    "metadata_sha256", "source_root", "overlay_base", "overlay", "unadmitted_paths_absent"}
                and isinstance(database["metadata_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", database["metadata_sha256"]) is not None
                and isinstance(database["source_root"], str) and bool(database["source_root"])
                and database["overlay_base"] is False and database["overlay"] is False
                and database["unadmitted_paths_absent"] == list(UNADMITTED_DATABASE_PATHS),
                "published database configuration identity differs")
    require(record["database_before"]["source_root"] == record["database_after"]["source_root"],
            "published database source root changed")
    postcheck = read_regular_snapshot(directory / "ANALYSIS_PLAN_AFTER.json",
                                      maximum=MAX_RECEIPT_BYTES, label="published analysis plan postcheck")
    require(postcheck.sha256 == record["postcheck_receipt_sha256"],
            "published analysis plan postcheck digest differs")
    require(parse_strict_json_bytes(postcheck.data, label="published analysis plan postcheck") == {
                "summary_plan": identity, "tool": tool, "database": record["database_after"],
                "qlconfig_sha256": hashlib.sha256(QLCONFIG).hexdigest()},
            "published analysis plan postcheck differs")
    failure = directory / "ANALYSIS_PLAN_FAILURE.json"
    require(not failure.exists() and not failure.is_symlink(), "published analysis plan postcheck failed")
